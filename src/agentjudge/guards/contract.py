"""合约守卫（Contract Guard）。

把“工具能做什么”写成合约，运行时逐项核对：

* 路径是否在允许区、是否踩到禁止区；
* 出网主机与 HTTP 方法是否被批准；
* 单次参数大小、单会话调用次数是否超限；
* 执行的脚本是否来自可信来源（本次会话刚写的脚本一律视为不可信）；
* 技能合约的信任状态（trusted / conditional / quarantined）。
"""

from __future__ import annotations

import re
import tempfile
from pathlib import Path

from ..contracts import Contract, path_matches
from ..taxonomy import ToolKind, normalize_path
from ..types import Action, Finding, Severity
from ..utils import host_matches, is_private_host, mask_secrets, truncate, url_host
from .base import Guard, GuardContext, finding

_SCRIPT_RE = re.compile(
    r"\b(?:bash|sh|zsh|ksh|python[0-9.]*|node|perl|ruby|pwsh|powershell)\s+(?:-\S+\s+)*([\w./~:\\-]+\.(?:sh|bash|py|js|mjs|pl|rb|ps1))",
    re.IGNORECASE,
)
_METHOD_RE = re.compile(r"\b(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b", re.IGNORECASE)


def _temp_patterns() -> list[str]:
    dirs = {"/tmp", "/var/tmp", "/dev/shm", tempfile.gettempdir()}
    out = []
    for d in dirs:
        norm = normalize_path(d)
        out.extend([f"{norm}/**", f"{norm}/*"])
    return out


class ContractGuard(Guard):
    name = "contract"
    description = "工具/技能合约一致性"

    def check(self, ctx: GuardContext) -> list[Finding]:
        opts = ctx.policy.guard(self.name).options
        findings: list[Finding] = []
        contract = ctx.contracts.for_tool(ctx.call.tool)

        # 1) 技能信任状态（若调用来自某个 skill）
        skill = ctx.call.skill
        if skill:
            skill_contract = ctx.contracts.skill(skill)
            if skill_contract is not None:
                findings.extend(self._skill_state(ctx, skill_contract))

        # 2) 未登记工具
        if contract is None:
            policy_unknown = str(opts.get("unknown_tool", "allow")).lower()
            if policy_unknown == "deny":
                findings.append(
                    finding(
                        self.name,
                        "CT-TOOL-001",
                        "未在合约中登记的工具",
                        severity=Severity.MEDIUM,
                        action=Action.DENY,
                        explain="策略要求所有工具必须先在 contracts/ 中登记。",
                        evidence={"tool": ctx.call.tool},
                        tags=["contract", "governance"],
                    )
                )
            elif policy_unknown == "escalate":
                findings.append(
                    finding(
                        self.name,
                        "CT-TOOL-002",
                        "未登记工具，转人工确认",
                        severity=Severity.LOW,
                        action=Action.ESCALATE,
                        explain="工具未登记合约，无法核对允许范围。",
                        evidence={"tool": ctx.call.tool},
                        tags=["contract", "governance"],
                    )
                )
            return findings

        # 3) 合约自身声明隔离
        if contract.status == "quarantined":
            findings.append(
                finding(
                    self.name,
                    "CT-SKILL-001",
                    "合约状态为隔离",
                    severity=Severity.CRITICAL,
                    action=Action.DENY,
                    explain="该工具/技能的合约在静态体检中被判定为隔离，禁止运行时调用。",
                    evidence={"tool": ctx.call.tool, "contract": contract.name},
                    tags=["contract", "skill"],
                )
            )
            return findings

        # 4) 条件信任：只允许声明过的能力
        if contract.status == "conditional" and contract.capabilities:
            kind = ctx.tool_kind.value
            if kind not in {c.lower() for c in contract.capabilities}:
                findings.append(
                    finding(
                        self.name,
                        "CT-SKILL-002",
                        "调用了未声明的能力",
                        severity=Severity.HIGH,
                        action=Action.ESCALATE,
                        explain=(
                            f"技能仅声明了 {contract.capabilities}，但本次调用属于 {kind}，"
                            "与“言行一致”原则冲突，需人工确认。"
                        ),
                        evidence={
                            "skill": skill or contract.skill_name,
                            "declared": contract.capabilities,
                            "observed": kind,
                        },
                        tags=["contract", "skill", "drift"],
                    )
                )

        # 5) 路径约束
        findings.extend(self._paths(ctx, contract))

        # 6) 网络约束
        findings.extend(self._network(ctx, contract))

        # 7) 参数大小与频次
        findings.extend(self._limits(ctx, contract))

        # 8) 脚本来源
        if ctx.tool_kind is ToolKind.SHELL and contract.require_trusted_script:
            findings.extend(self._script(ctx, contract))
        return findings

    # -- 技能状态 ---------------------------------------------------------
    def _skill_state(self, ctx: GuardContext, skill_contract: Contract) -> list[Finding]:
        status = skill_contract.status
        if status == "quarantined":
            return [
                finding(
                    self.name,
                    "CT-SKILL-001",
                    "技能静态体检未通过（隔离）",
                    severity=Severity.CRITICAL,
                    action=Action.DENY,
                    explain="技能的文档声明与代码实测严重不一致，已隔离。",
                    evidence={"skill": skill_contract.skill_name, "contract": skill_contract.source},
                    tags=["contract", "skill"],
                )
            ]
        if status == "conditional":
            kind = ctx.tool_kind.value
            if skill_contract.capabilities and kind not in {c.lower() for c in skill_contract.capabilities}:
                return [
                    finding(
                        self.name,
                        "CT-SKILL-002",
                        "技能调用了未声明的能力",
                        severity=Severity.HIGH,
                        action=Action.ESCALATE,
                        explain="技能处于条件信任状态，只能使用已声明的能力。",
                        evidence={
                            "skill": skill_contract.skill_name,
                            "declared": skill_contract.capabilities,
                            "observed": kind,
                        },
                        tags=["contract", "skill", "drift"],
                    )
                ]
        return []

    # -- 路径 -------------------------------------------------------------
    def _paths(self, ctx: GuardContext, contract: Contract) -> list[Finding]:
        kind = ctx.tool_kind
        path = ctx.call.path
        if not path:
            return []
        findings: list[Finding] = []
        reading = kind is ToolKind.FS_READ
        deny_list = contract.deny_read if reading else contract.deny_write
        allow_list = contract.allow_read if reading else contract.allow_write

        matched_deny = path_matches(path, deny_list)
        if matched_deny:
            findings.append(
                finding(
                    self.name,
                    "CT-PATH-DENY-001",
                    "路径命中合约禁止区",
                    severity=Severity.CRITICAL if not reading else Severity.HIGH,
                    action=Action.DENY,
                    explain=f"路径 {path} 命中合约禁止模式 {matched_deny}。",
                    evidence={"path": truncate(path, 200), "pattern": matched_deny, "operation": kind.value},
                    tags=["contract", "path"],
                )
            )
            return findings

        if allow_list:
            matched_allow = path_matches(path, allow_list)
            if not matched_allow:
                findings.append(
                    finding(
                        self.name,
                        "CT-PATH-ALLOW-001",
                        "路径不在合约允许区",
                        severity=Severity.HIGH if not reading else Severity.MEDIUM,
                        action=Action.DENY if not reading else Action.ESCALATE,
                        explain=f"路径 {path} 未命中任何允许模式，按最小权限原则收紧。",
                        evidence={
                            "path": truncate(path, 200),
                            "allow": allow_list[:6],
                            "operation": kind.value,
                        },
                        tags=["contract", "path"],
                    )
                )
        return findings

    # -- 网络 -------------------------------------------------------------
    def _network(self, ctx: GuardContext, contract: Contract) -> list[Finding]:
        if ctx.tool_kind is not ToolKind.NETWORK:
            return []
        url = ctx.call.url
        host = url_host(url)
        if not host:
            return [
                finding(
                    self.name,
                    "CT-NET-000",
                    "网络调用缺少明确目标",
                    severity=Severity.MEDIUM,
                    action=Action.ESCALATE,
                    explain="无法从参数中解析出目标主机，无法核对白名单。",
                    evidence={"tool": ctx.call.tool, "args": truncate(str(ctx.call.args), 200)},
                    tags=["contract", "network"],
                )
            ]
        method = str(ctx.call.arg("method", "http_method", default="") or "").upper()
        if not method:
            match = _METHOD_RE.search(url + " " + str(ctx.call.args))
            method = match.group(1).upper() if match else "GET"

        allow = contract.allow_hosts or ctx.policy.network.allow_hosts
        if host_matches(host, allow) or is_private_host(host):
            if contract.allow_methods and method not in contract.allow_methods:
                return [
                    finding(
                        self.name,
                        "CT-NET-003",
                        "HTTP 方法未被合约允许",
                        severity=Severity.HIGH,
                        action=Action.DENY,
                        explain=f"{host} 仅允许 {contract.allow_methods}，本次为 {method}。",
                        evidence={"host": host, "method": method, "allowed": contract.allow_methods},
                        tags=["contract", "network"],
                    )
                ]
            return []

        if method in {"POST", "PUT", "PATCH", "DELETE"}:
            return [
                finding(
                    self.name,
                    "CT-NET-002",
                    "向非白名单主机发送写请求",
                    severity=Severity.CRITICAL,
                    action=Action.DENY,
                    explain=f"{method} {host} 不在允许列表，可能用于数据外泄或远程控制。",
                    evidence={"host": host, "method": method, "url": mask_secrets(truncate(url, 200))},
                    tags=["contract", "network", "exfiltration"],
                )
            ]
        return [
            finding(
                self.name,
                "CT-NET-001",
                "访问非白名单主机",
                severity=Severity.MEDIUM,
                action=Action.ESCALATE,
                explain=f"{host} 不在允许列表，转人工确认。",
                evidence={"host": host, "method": method, "url": truncate(url, 200)},
                tags=["contract", "network"],
            )
        ]

    # -- 限额 -------------------------------------------------------------
    def _limits(self, ctx: GuardContext, contract: Contract) -> list[Finding]:
        size = sum(len(v) for v in ctx.call.text_blobs().values())
        findings: list[Finding] = []
        if size > contract.max_arg_bytes:
            findings.append(
                finding(
                    self.name,
                    "CT-LIMIT-001",
                    "单次调用参数超过合约上限",
                    severity=Severity.HIGH,
                    action=Action.DENY,
                    explain=f"参数 {size} 字节 > 上限 {contract.max_arg_bytes}，可能是批量倾倒。",
                    evidence={"bytes": size, "limit": contract.max_arg_bytes},
                    tags=["contract", "limit"],
                )
            )
        calls = sum(1 for s in ctx.session.steps if s.tool == ctx.call.tool)
        if contract.max_calls_per_session and calls >= contract.max_calls_per_session:
            findings.append(
                finding(
                    self.name,
                    "CT-LIMIT-002",
                    "单会话调用次数超限",
                    severity=Severity.MEDIUM,
                    action=Action.ESCALATE,
                    explain=f"{ctx.call.tool} 已调用 {calls} 次，超过 {contract.max_calls_per_session}。",
                    evidence={"tool": ctx.call.tool, "calls": calls},
                    tags=["contract", "limit"],
                )
            )
        return findings

    # -- 脚本来源 ---------------------------------------------------------
    def _script(self, ctx: GuardContext, contract: Contract) -> list[Finding]:
        command = ctx.call.command
        match = _SCRIPT_RE.search(command)
        if not match:
            return []
        script = match.group(1)
        norm = normalize_path(script)
        temp_patterns = _temp_patterns()

        trusted = path_matches(script, contract.trusted_script_dirs)
        if path_matches(script, temp_patterns):
            return [
                finding(
                    self.name,
                    "CT-SCRIPT-001",
                    "执行临时目录中的脚本",
                    severity=Severity.HIGH,
                    action=Action.DENY,
                    explain=f"脚本 {script} 位于临时目录，内容不可追溯，易被载荷注入。",
                    evidence={"script": script, "command": truncate(command, 200)},
                    tags=["contract", "script"],
                )
            ]
        if norm in {normalize_path(p) for p in ctx.session.written_paths}:
            return [
                finding(
                    self.name,
                    "CT-SCRIPT-002",
                    "执行本次会话刚写入的脚本",
                    severity=Severity.HIGH,
                    action=Action.DENY,
                    explain=(
                        f"脚本 {script} 由本次会话生成，未经审批即执行等同于"
                        "“写文件 → 执行”的绕过链。"
                    ),
                    evidence={"script": script, "command": truncate(command, 200)},
                    tags=["contract", "script", "persistence"],
                )
            ]
        if trusted:
            return []
        workspace = normalize_path(ctx.policy.workspace_root or str(Path.cwd()))
        if Path(script).is_absolute() and not path_matches(script, [workspace + "/**"]):
            return [
                finding(
                    self.name,
                    "CT-SCRIPT-003",
                    "执行工作区外的脚本",
                    severity=Severity.MEDIUM,
                    action=Action.ESCALATE,
                    explain=f"脚本 {script} 不在工作区也不在可信目录，转人工确认。",
                    evidence={"script": script, "trusted_dirs": contract.trusted_script_dirs[:4]},
                    tags=["contract", "script"],
                )
            ]
        return [
            finding(
                self.name,
                "CT-SCRIPT-004",
                "脚本不在可信目录",
                severity=Severity.HIGH,
                action=Action.DENY,
                explain=(
                    f"脚本 {script} 不在可信目录 {contract.trusted_script_dirs[:4]} 中。"
                    "只允许执行已登记目录内的脚本，避免“写文件 → 执行”的绕过链。"
                ),
                evidence={"script": script, "command": truncate(command, 200)},
                tags=["contract", "script"],
            )
        ]
