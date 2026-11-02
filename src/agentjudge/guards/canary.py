"""蜜标守卫（Canary Guard）。

会话创建时注入若干不可预测的蜜标（canary token），并“种”进诱饵文件、
环境变量或配置里。正常任务是永远不会读取/发送它们的；一旦蜜标出现在
任何调用的参数里，就说明发生了越权读取或数据外泄。
"""

from __future__ import annotations

import secrets

from ..types import Action, Finding, Severity
from ..utils import mask_secrets, truncate
from .base import Guard, GuardContext, finding
from .stego import decode_views

CANARY_PREFIX = "AJ-CANARY-"


def new_canary(nbytes: int = 6) -> str:
    return f"{CANARY_PREFIX}{secrets.token_hex(nbytes).upper()}"


class CanaryGuard(Guard):
    name = "canary"
    description = "蜜标令牌外泄检测"

    def check(self, ctx: GuardContext) -> list[Finding]:
        tokens = [t for t in ctx.session.canaries if t]
        if not tokens:
            return []
        blobs = ctx.blobs()
        texts: list[tuple[str, str]] = [(k, v) for k, v in blobs.items() if v and k != "tool"]
        for field, text in list(texts):
            for view in decode_views(text):
                texts.append((f"{field}(decoded)", view))

        findings: list[Finding] = []
        for token in tokens:
            hit_field = ""
            for field, text in texts:
                if token in text:
                    hit_field = field
                    break
            if hit_field:
                findings.append(
                    finding(
                        self.name,
                        "CANARY-001",
                        "蜜标令牌出现在调用参数中",
                        severity=Severity.CRITICAL,
                        action=Action.DENY,
                        explain=(
                            "该令牌只存在于诱饵文件/环境变量中，正常任务不会读取它。"
                            "出现即说明越权读取或数据外泄链已经形成。"
                        ),
                        evidence={
                            "field": hit_field,
                            "token": mask_secrets(token),
                            "planted_at": ctx.session.canary_locations.get(token, "诱饵资源"),
                        },
                        tags=["canary", "exfiltration"],
                    )
                )
                continue
            # 片段命中：可能是被截断/分片外泄，转人工复核
            prefix = token[: len(CANARY_PREFIX) + 4]
            for field, text in texts:
                if prefix in text:
                    findings.append(
                        finding(
                            self.name,
                            "CANARY-002",
                            "蜜标片段命中（疑似分片外泄）",
                            severity=Severity.HIGH,
                            action=Action.ESCALATE,
                            explain="仅命中蜜标前缀，可能是分片或截断传输，需要人工确认。",
                            evidence={"field": field, "prefix": prefix, "text": truncate(text, 120)},
                            tags=["canary", "exfiltration"],
                        )
                    )
                    break
        return findings
