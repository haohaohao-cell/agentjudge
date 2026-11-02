"""工具合约（Tool Contract）与技能合约（Skill Contract）。

合约把“这个工具允许做什么”变成可机读、可版本化的声明：

* 路径白/黑名单（读、写）
* 出网主机白名单
* 参数大小、单会话调用次数上限
* 脚本执行是否要求可信来源

技能合约由 ``agentjudge skill inspect`` 生成，记录“文档声称 / 代码实测”的
言行矩阵与信任状态，供运行时按声明能力收紧权限。
"""

from __future__ import annotations

import fnmatch
import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .errors import ContractError
from .taxonomy import normalize_path
from .utils import read_text_utf8

TRUST_STATES = {"trusted", "conditional", "quarantined", "unknown"}


def _expand(pattern: str, workspace: str) -> str:
    p = pattern.strip()
    if "{{workspace}}" in p:
        p = p.replace("{{workspace}}", workspace or ".")
    p = os.path.expandvars(p)
    if p.startswith("~"):
        p = os.path.expanduser(p)
    return normalize_path(p, workspace or "")


def path_matches(path: str, patterns: list[str]) -> str | None:
    """返回命中的模式（便于审计解释），未命中返回 ``None``。"""
    if not patterns:
        return None
    norm = normalize_path(path)
    candidates = {norm}
    if not norm.startswith(("./", "/", "c:", "~")) and not norm.startswith(".."):
        candidates.add(f"./{norm}")
    for pat in patterns:
        for cand in candidates:
            if fnmatch.fnmatchcase(cand, pat) or fnmatch.fnmatchcase("/" + cand.lstrip("./"), pat):
                return pat
    return None


@dataclass(slots=True)
class Contract:
    name: str
    kind: str = ""
    match: list[str] = field(default_factory=list)
    description: str = ""
    allow_read: list[str] = field(default_factory=list)
    deny_read: list[str] = field(default_factory=list)
    allow_write: list[str] = field(default_factory=list)
    deny_write: list[str] = field(default_factory=list)
    allow_hosts: list[str] = field(default_factory=list)
    allow_methods: list[str] = field(default_factory=list)
    max_arg_bytes: int = 262_144
    max_calls_per_session: int = 500
    require_trusted_script: bool = False
    trusted_script_dirs: list[str] = field(default_factory=list)
    status: str = "trusted"
    capabilities: list[str] = field(default_factory=list)
    skill_name: str = ""
    source: str = ""

    @classmethod
    def from_mapping(cls, data: dict[str, Any], *, source: str = "") -> Contract:
        tool = data.get("tool", {}) or {}
        paths = data.get("paths", {}) or {}
        net = data.get("network", {}) or {}
        limits = data.get("limits", {}) or {}
        scripts = data.get("scripts", {}) or {}
        skill = data.get("skill", {}) or {}
        contract = cls(
            name=str(tool.get("name") or data.get("name") or ""),
            kind=str(tool.get("kind", "")),
            match=[str(x) for x in tool.get("match", [])],
            description=str(tool.get("description", "")),
            allow_read=[str(x) for x in paths.get("allow_read", paths.get("allow", []))],
            deny_read=[str(x) for x in paths.get("deny_read", paths.get("deny", []))],
            allow_write=[str(x) for x in paths.get("allow_write", [])],
            deny_write=[str(x) for x in paths.get("deny_write", paths.get("deny", []))],
            allow_hosts=[str(x) for x in net.get("allow_hosts", [])],
            allow_methods=[str(x).upper() for x in net.get("methods", [])],
            max_arg_bytes=int(limits.get("max_arg_bytes", 262_144)),
            max_calls_per_session=int(limits.get("max_calls_per_session", 500)),
            require_trusted_script=bool(scripts.get("require_trusted", False)),
            trusted_script_dirs=[str(x) for x in scripts.get("trusted_dirs", [])],
            status=str(skill.get("status", "trusted")),
            capabilities=[str(x) for x in skill.get("capabilities", [])],
            skill_name=str(skill.get("name", "")),
            source=source,
        )
        if contract.status not in TRUST_STATES:
            raise ContractError(f"合约 {source} 的 status 非法: {contract.status}")
        if not contract.name:
            raise ContractError(f"合约 {source} 缺少 tool.name")
        return contract

    def matches(self, tool: str) -> bool:
        if tool == self.name:
            return True
        return any(fnmatch.fnmatchcase(tool, pat) for pat in self.match)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "kind": self.kind,
            "match": self.match,
            "description": self.description,
            "allow_read": self.allow_read,
            "deny_read": self.deny_read,
            "allow_write": self.allow_write,
            "deny_write": self.deny_write,
            "allow_hosts": self.allow_hosts,
            "allow_methods": self.allow_methods,
            "max_arg_bytes": self.max_arg_bytes,
            "max_calls_per_session": self.max_calls_per_session,
            "require_trusted_script": self.require_trusted_script,
            "trusted_script_dirs": self.trusted_script_dirs,
            "status": self.status,
            "capabilities": self.capabilities,
            "skill_name": self.skill_name,
            "source": self.source,
        }


class ContractBook:
    """合约集合；按工具名查找，支持通配。"""

    def __init__(self, contracts: list[Contract] | None = None, workspace: str = "") -> None:
        self._contracts: list[Contract] = list(contracts or [])
        self.workspace = workspace
        self._lock_sources: dict[str, str] = {}
        self._compile()

    def _compile(self) -> None:
        ws = self.workspace
        for c in self._contracts:
            c.allow_read = [_expand(p, ws) for p in c.allow_read]
            c.deny_read = [_expand(p, ws) for p in c.deny_read]
            c.allow_write = [_expand(p, ws) for p in c.allow_write]
            c.deny_write = [_expand(p, ws) for p in c.deny_write]
            c.trusted_script_dirs = [_expand(p, ws) for p in c.trusted_script_dirs]

    @classmethod
    def load_dir(cls, directory: str | Path, workspace: str = "") -> ContractBook:
        contracts: list[Contract] = []
        root = Path(directory)
        if not root.exists():
            return cls([], workspace)
        for path in sorted(root.rglob("*.toml")):
            contracts.append(cls._load_file(path))
        return cls(contracts, workspace)

    @staticmethod
    def _load_file(path: Path) -> Contract:
        try:
            data = tomllib.loads(read_text_utf8(path))
        except (OSError, tomllib.TOMLDecodeError) as exc:
            raise ContractError(f"合约解析失败 {path}: {exc}") from exc
        return Contract.from_mapping(data, source=str(path))

    def add(self, contract: Contract) -> None:
        self._contracts.append(contract)
        self._compile()

    def for_tool(self, tool: str) -> Contract | None:
        exact = [c for c in self._contracts if c.name == tool]
        if exact:
            return exact[0]
        for c in self._contracts:
            if c.match and c.matches(tool):
                return c
        return None

    def skill(self, skill_name: str) -> Contract | None:
        if not skill_name:
            return None
        for c in self._contracts:
            if c.skill_name and c.skill_name == skill_name:
                return c
        return None

    def all(self) -> list[Contract]:
        return list(self._contracts)

    def __len__(self) -> int:
        return len(self._contracts)

    def __iter__(self):
        return iter(self._contracts)

    def to_dict(self) -> dict[str, Any]:
        return {"count": len(self._contracts), "contracts": [c.to_dict() for c in self._contracts]}
