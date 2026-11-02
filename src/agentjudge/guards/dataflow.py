"""跨步骤数据流守卫（DataFlow Guard）。

这是 AgentJudge 与传统“单次调用拦截”的分水岭：判定对象不是单个工具，
而是“敏感数据从哪来、到哪去”的会话级数据流。

判定规则：

* 敏感数据 → 出网发送：拒绝（凭据外泄链）
* 敏感数据 → 命令执行：拒绝
* 敏感数据 → 本地写入：仅记录数据流边（不阻断，避免过度打扰）
* 注入指令数据 → 进入执行/外发路径：拒绝
* 会话中已出现被隔离的注入内容：后续危险动作一律拒绝
"""

from __future__ import annotations

from ..session import FlowHit
from ..taxonomy import Sink
from ..types import Action, Finding, Severity
from ..utils import mask_secrets, truncate
from .base import Guard, GuardContext, finding
from .stego import decode_views

SENSITIVE_PREFIXES = ("credential:", "secret:", "canary:", "pii:")
DANGEROUS_SINKS = {Sink.NET_EXTERNAL, Sink.EXEC, Sink.WRITE}


def _edges(hits: list[FlowHit]) -> list[dict[str, object]]:
    return [hit.to_dict() for hit in hits]


class DataFlowGuard(Guard):
    name = "dataflow"
    description = "跨步骤数据流与污点传播"

    def check(self, ctx: GuardContext) -> list[Finding]:
        call = ctx.call
        session = ctx.session
        sink = ctx.sink
        opts = ctx.policy.guard(self.name).options
        report_write = bool(opts.get("report_write_flows", True))

        text = call.all_text()
        views = decode_views(text)
        hits = session.propagate(text, decoded_views=views)
        ctx.state["flow_hits"] = hits
        findings: list[Finding] = []

        instruction_hits = [
            h for h in hits if any(str(k).startswith("instruction:") for k in h.labels)
        ]
        sensitive_hits = [
            h for h in hits if any(str(k).startswith(SENSITIVE_PREFIXES) for k in h.labels)
        ]

        # 1) 会话已被注入污染：危险动作一律收紧
        if session.instruction_sources() and sink in DANGEROUS_SINKS:
            if sink is Sink.WRITE:
                findings.append(
                    finding(
                        self.name,
                        "DF-QUAR-002",
                        "注入污染会话中的写入动作",
                        severity=Severity.MEDIUM,
                        action=Action.ESCALATE,
                        explain="本会话读取过含注入指令的内容，写入动作需人工确认落点。",
                        evidence={"sink": sink.value, "tool": call.tool},
                        tags=["dataflow", "instruction"],
                    )
                )
            else:
                findings.append(
                    finding(
                        self.name,
                        "DF-QUAR-001",
                        "注入污染会话中的危险动作",
                        severity=Severity.CRITICAL,
                        action=Action.DENY,
                        explain=(
                            "本会话已读取含注入指令的内容（读取即隔离），"
                            "后续执行/外发动作按“权限单向收紧”直接拒绝。"
                        ),
                        evidence={
                            "sink": sink.value,
                            "sources": [a.to_dict() for a in session.instruction_sources()[:3]],
                        },
                        tags=["dataflow", "instruction", "fail_closed"],
                    )
                )

        # 2) 注入指令数据流入执行/外发路径
        if instruction_hits and sink in {Sink.EXEC, Sink.NET_EXTERNAL, Sink.NET_INTERNAL}:
            findings.append(
                finding(
                    self.name,
                    "DF-INJ-001",
                    "指令型数据流入危险路径",
                    severity=Severity.CRITICAL,
                    action=Action.DENY,
                    explain="来自外部内容（文档/网页/记忆）的指令正在驱动执行或外发，等价于提示注入落地。",
                    evidence={"sink": sink.value, "edges": _edges(instruction_hits)[:4]},
                    tags=["dataflow", "instruction"],
                )
            )

        # 3) 敏感数据 → 出网
        if sensitive_hits and sink is Sink.NET_EXTERNAL:
            findings.append(
                finding(
                    self.name,
                    "DF-EXFIL-001",
                    "敏感数据流向外部网络",
                    severity=Severity.CRITICAL,
                    action=Action.DENY,
                    explain=(
                        "当前参数携带了此前步骤读到的敏感数据，并准备发送到外部主机——"
                        "单步看每步都合规，串起来就是外泄链。"
                    ),
                    evidence={
                        "sink": sink.value,
                        "host": call.arg("url", "endpoint", default=""),
                        "sample": mask_secrets(truncate(text, 160)),
                        "edges": _edges(sensitive_hits)[:4],
                    },
                    tags=["dataflow", "exfiltration", "session_level"],
                )
            )

        # 4) 敏感数据 → 命令执行
        if sensitive_hits and sink is Sink.EXEC:
            findings.append(
                finding(
                    self.name,
                    "DF-EXEC-001",
                    "敏感数据进入命令执行",
                    severity=Severity.HIGH,
                    action=Action.DENY,
                    explain="敏感数据被拼进命令行，可能通过编码、打印或二次外发泄露。",
                    evidence={"sink": sink.value, "edges": _edges(sensitive_hits)[:4]},
                    tags=["dataflow", "execution"],
                )
            )

        # 5) 敏感数据 → 内网发送：可疑但需人工确认
        if sensitive_hits and sink is Sink.NET_INTERNAL:
            findings.append(
                finding(
                    self.name,
                    "DF-INT-001",
                    "敏感数据发往内网地址",
                    severity=Severity.MEDIUM,
                    action=Action.ESCALATE,
                    explain="内网目标虽非公网，但凭据外传仍可能造成横向移动。",
                    evidence={"sink": sink.value, "edges": _edges(sensitive_hits)[:3]},
                    tags=["dataflow", "exfiltration"],
                )
            )

        # 6) 敏感数据 → 本地写入：记录数据流边，不阻断
        if sensitive_hits and sink is Sink.WRITE and report_write:
            findings.append(
                finding(
                    self.name,
                    "DF-WRITE-001",
                    "敏感数据落盘（已记录）",
                    severity=Severity.LOW,
                    action=Action.ALLOW,
                    explain="敏感数据写入本地文件，仅记录数据流边以备追溯。",
                    evidence={"sink": sink.value, "edges": _edges(sensitive_hits)[:3]},
                    tags=["dataflow", "informational"],
                )
            )

        return findings
