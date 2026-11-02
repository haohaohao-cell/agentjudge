"""策略加载与校验。

策略使用 TOML（Python 3.11+ 标准库 ``tomllib``），保持零依赖。
所有相对路径都相对于工作目录（``base_dir``）解析，便于部署时整体搬移。
"""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .errors import PolicyError
from .types import Action, Severity
from .version import POLICY_SCHEMA_VERSION

DEFAULT_TARGETS = ["command", "path", "url", "arg.*", "content"]
ALLOWED_MODES = {"enforce", "monitor"}
ALLOWED_PROVIDERS = {"none", "openai", "openai_compat", "ollama"}
ALLOWED_ON_ERROR = {"deny", "escalate"}


@dataclass(slots=True)
class RuleConfig:
    """一条确定性规则。"""

    id: str
    title: str
    pattern: str
    severity: Severity = Severity.HIGH
    action: Action = Action.DENY
    targets: list[str] = field(default_factory=lambda: list(DEFAULT_TARGETS))
    explain: str = ""
    tags: list[str] = field(default_factory=list)
    unless_host_allowed: bool = False
    enabled: bool = True
    regex: re.Pattern[str] = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        if not self.id or not self.pattern:
            raise PolicyError("rule 需要 id 与 pattern")
        try:
            self.regex = re.compile(self.pattern, re.IGNORECASE | re.MULTILINE)
        except re.error as exc:  # pragma: no cover - 配置错误路径
            raise PolicyError(f"规则 {self.id} 的正则非法: {exc}") from exc
        if isinstance(self.severity, str):
            self.severity = Severity(self.severity)
        if isinstance(self.action, str):
            self.action = Action(self.action)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "pattern": self.pattern,
            "severity": self.severity.value,
            "action": self.action.value,
            "targets": self.targets,
            "explain": self.explain,
            "tags": self.tags,
            "unless_host_allowed": self.unless_host_allowed,
            "enabled": self.enabled,
        }


@dataclass(slots=True)
class GuardConfig:
    enabled: bool = True
    options: dict[str, Any] = field(default_factory=dict)

    def get(self, key: str, default: Any = None) -> Any:
        return self.options.get(key, default)

    def to_dict(self) -> dict[str, Any]:
        return {"enabled": self.enabled, **self.options}


@dataclass(slots=True)
class WatcherConfig:
    enabled: bool = True
    provider: str = "none"
    base_url: str = "https://api.openai.com/v1"
    model: str = "gpt-4o-mini"
    api_key_env: str = "AGENTJUDGE_LLM_KEY"
    max_rounds: int = 8
    timeout_s: float = 20.0
    min_confidence: float = 0.75
    can_release: bool = False
    on_error: str = "deny"
    max_evidence: int = 8

    def __post_init__(self) -> None:
        if self.provider not in ALLOWED_PROVIDERS:
            raise PolicyError(f"watcher.provider 不支持: {self.provider}（可选 {sorted(ALLOWED_PROVIDERS)}）")
        if self.on_error not in ALLOWED_ON_ERROR:
            raise PolicyError(f"watcher.on_error 非法: {self.on_error}")
        self.max_rounds = int(self.max_rounds)
        if not 1 <= self.max_rounds <= 32:
            raise PolicyError("watcher.max_rounds 必须在 1..32 之间")

    def to_dict(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "provider": self.provider,
            "model": self.model,
            "max_rounds": self.max_rounds,
            "timeout_s": self.timeout_s,
            "min_confidence": self.min_confidence,
            "can_release": self.can_release,
            "on_error": self.on_error,
        }


@dataclass(slots=True)
class AuditConfig:
    db_path: str = "var/agentjudge.db"
    anchor_path: str = "var/tail.anchor"
    key_file: str = "var/hmac.key"
    key_env: str = "AGENTJUDGE_HMAC_KEY"
    key_id: str = "k1"
    seal_interval_s: int = 300
    max_payload_chars: int = 4000

    def to_dict(self) -> dict[str, Any]:
        return {
            "db_path": self.db_path,
            "anchor_path": self.anchor_path,
            "key_file": self.key_file,
            "seal_interval_s": self.seal_interval_s,
            "key_id": self.key_id,
        }


@dataclass(slots=True)
class NetworkConfig:
    allow_hosts: list[str] = field(
        default_factory=lambda: ["localhost", "127.0.0.1", "::1", "github.com", "docs.python.org", "pypi.org"]
    )
    internal_hosts: list[str] = field(
        default_factory=lambda: ["localhost", "127.0.0.1", "::1", "*.internal", "*.local"]
    )

    def is_allowed_host(self, host: str) -> bool:
        from .utils import host_matches

        return host_matches(host, self.allow_hosts)

    def to_dict(self) -> dict[str, Any]:
        return {"allow_hosts": self.allow_hosts, "internal_hosts": self.internal_hosts}


@dataclass(slots=True)
class Policy:
    """完整策略。"""

    schema: int = POLICY_SCHEMA_VERSION
    name: str = "baseline"
    version: str = "0.1.0"
    mode: str = "enforce"
    fail_closed_action: Action = Action.DENY
    workspace_root: str = ""
    contracts_dir: str = "contracts"
    base_dir: str = "."
    thresholds: dict[str, int] = field(default_factory=lambda: {"escalate_at": 30, "deny_at": 70})
    network: NetworkConfig = field(default_factory=NetworkConfig)
    watcher: WatcherConfig = field(default_factory=WatcherConfig)
    audit: AuditConfig = field(default_factory=AuditConfig)
    guards: dict[str, GuardConfig] = field(default_factory=dict)
    rules: list[RuleConfig] = field(default_factory=list)
    source_path: str = "<builtin>"

    # -- 生命周期 ---------------------------------------------------------
    @classmethod
    def load(cls, path: str | Path, base_dir: str | Path | None = None) -> Policy:
        p = Path(path)
        if not p.exists():
            raise PolicyError(f"策略文件不存在: {p}")
        mapping = _load_with_extends(p.resolve(), seen=set())
        policy = cls.from_mapping(mapping, base_dir=base_dir if base_dir is not None else Path.cwd())
        policy.source_path = str(p.resolve())
        return policy

    @classmethod
    def from_mapping(cls, data: dict[str, Any], base_dir: str | Path = ".") -> Policy:
        policy = cls(base_dir=str(base_dir))
        policy._apply(data)
        policy._validate()
        return policy

    # -- 解析 -------------------------------------------------------------
    def _apply(self, data: dict[str, Any]) -> None:
        self.schema = int(data.get("schema", POLICY_SCHEMA_VERSION))
        if self.schema > POLICY_SCHEMA_VERSION:
            raise PolicyError(f"策略 schema {self.schema} 高于本版本支持的 {POLICY_SCHEMA_VERSION}")
        self.name = str(data.get("name", self.name))
        self.version = str(data.get("version", self.version))
        self.mode = str(data.get("mode", self.mode)).lower()
        fc = str(data.get("fail_closed_action", "deny")).lower()
        if fc == "allow":
            raise PolicyError("fail_closed_action 不允许为 allow：失败必须收紧，不能放行")
        self.fail_closed_action = Action(fc)
        self.workspace_root = str(data.get("workspace_root", self.workspace_root) or "")
        self.contracts_dir = str(data.get("contracts_dir", self.contracts_dir))

        th = data.get("thresholds", {}) or {}
        self.thresholds = {
            "escalate_at": int(th.get("escalate_at", 30)),
            "deny_at": int(th.get("deny_at", 70)),
        }

        net = data.get("network", {}) or {}
        self.network = NetworkConfig(
            allow_hosts=[str(x) for x in net.get("allow_hosts", NetworkConfig().allow_hosts)],
            internal_hosts=[str(x) for x in net.get("internal_hosts", NetworkConfig().internal_hosts)],
        )

        watcher = data.get("watcher", {}) or {}
        defaults = WatcherConfig()
        self.watcher = WatcherConfig(
            enabled=bool(watcher.get("enabled", defaults.enabled)),
            provider=str(watcher.get("provider", defaults.provider)),
            base_url=str(watcher.get("base_url", defaults.base_url)),
            model=str(watcher.get("model", defaults.model)),
            api_key_env=str(watcher.get("api_key_env", defaults.api_key_env)),
            max_rounds=int(watcher.get("max_rounds", defaults.max_rounds)),
            timeout_s=float(watcher.get("timeout_s", defaults.timeout_s)),
            min_confidence=float(watcher.get("min_confidence", defaults.min_confidence)),
            can_release=bool(watcher.get("can_release", defaults.can_release)),
            on_error=str(watcher.get("on_error", defaults.on_error)),
            max_evidence=int(watcher.get("max_evidence", defaults.max_evidence)),
        )

        audit = data.get("audit", {}) or {}
        adefault = AuditConfig()
        self.audit = AuditConfig(
            db_path=str(audit.get("db_path", adefault.db_path)),
            anchor_path=str(audit.get("anchor_path", adefault.anchor_path)),
            key_file=str(audit.get("key_file", adefault.key_file)),
            key_env=str(audit.get("key_env", adefault.key_env)),
            key_id=str(audit.get("key_id", adefault.key_id)),
            seal_interval_s=int(audit.get("seal_interval_s", adefault.seal_interval_s)),
            max_payload_chars=int(audit.get("max_payload_chars", adefault.max_payload_chars)),
        )

        guards: dict[str, GuardConfig] = {}
        for gname, gval in (data.get("guards", {}) or {}).items():
            if isinstance(gval, bool):
                guards[gname] = GuardConfig(enabled=gval)
            elif isinstance(gval, dict):
                opts = dict(gval)
                guards[gname] = GuardConfig(enabled=bool(opts.pop("enabled", True)), options=opts)
            else:
                raise PolicyError(f"guards.{gname} 类型非法")
        self.guards = guards

        rules: list[RuleConfig] = []
        raw_rules = data.get("rules", []) or []
        if isinstance(raw_rules, dict):  # 允许 [rules.xxx] 形式
            raw_rules = [{"id": k, **v} for k, v in raw_rules.items()]
        for i, raw in enumerate(raw_rules):
            if "title" not in raw and "pattern" in raw:
                raw = {"title": raw["id"], **raw}
            rules.append(
                RuleConfig(
                    id=str(raw.get("id", f"rule-{i}")),
                    title=str(raw.get("title", raw.get("id", f"rule-{i}"))),
                    pattern=str(raw["pattern"]),
                    severity=Severity(str(raw.get("severity", "high"))),
                    action=Action(str(raw.get("action", "deny"))),
                    targets=[str(t) for t in raw.get("targets", DEFAULT_TARGETS)],
                    explain=str(raw.get("explain", "")),
                    tags=[str(t) for t in raw.get("tags", [])],
                    unless_host_allowed=bool(raw.get("unless_host_allowed", False)),
                    enabled=bool(raw.get("enabled", True)),
                )
            )
        ids = [r.id for r in rules]
        dup = {x for x in ids if ids.count(x) > 1}
        if dup:
            raise PolicyError(f"规则 id 重复: {sorted(dup)}")
        self.rules = rules

    def _validate(self) -> None:
        if self.mode not in ALLOWED_MODES:
            raise PolicyError(f"mode 非法: {self.mode}（可选 {sorted(ALLOWED_MODES)}）")
        lo = self.thresholds["escalate_at"]
        hi = self.thresholds["deny_at"]
        if not 0 <= lo <= hi <= 100:
            raise PolicyError("thresholds 需满足 0 <= escalate_at <= deny_at <= 100")

    # -- 查询 -------------------------------------------------------------
    @property
    def version_label(self) -> str:
        return f"{self.name}@{self.version}"

    def resolve(self, path: str | Path) -> Path:
        p = Path(path)
        if p.is_absolute():
            return p
        return (Path(self.base_dir) / p).resolve()

    def guard(self, name: str, default_enabled: bool = True) -> GuardConfig:
        cfg = self.guards.get(name)
        if cfg is None:
            return GuardConfig(enabled=default_enabled)
        return cfg

    def enabled_rules(self) -> list[RuleConfig]:
        return [r for r in self.rules if r.enabled]

    def rule(self, rule_id: str) -> RuleConfig | None:
        for r in self.rules:
            if r.id == rule_id:
                return r
        return None

    def public(self) -> dict[str, Any]:
        """给 API/工作台用的策略快照（不含密钥路径）。"""
        return {
            "schema": self.schema,
            "name": self.name,
            "version": self.version,
            "version_label": self.version_label,
            "mode": self.mode,
            "fail_closed_action": self.fail_closed_action.value,
            "thresholds": self.thresholds,
            "network": self.network.to_dict(),
            "watcher": self.watcher.to_dict(),
            "guards": {k: v.to_dict() for k, v in self.guards.items()},
            "rules": [r.to_dict() for r in self.rules],
            "rule_count": len(self.rules),
            "contracts_dir": self.contracts_dir,
            "source_path": self.source_path,
        }


def _load_with_extends(path: Path, seen: set[str]) -> dict[str, Any]:
    """加载策略，支持 ``extend = "base.toml"`` 继承（深度合并，后者覆盖前者）。"""
    key = str(path)
    if key in seen:
        raise PolicyError(f"策略继承出现循环引用: {path}")
    seen.add(key)
    try:
        with path.open("rb") as fh:
            data = tomllib.load(fh)
    except tomllib.TOMLDecodeError as exc:
        raise PolicyError(f"策略 TOML 解析失败 {path}: {exc}") from exc
    base_name = data.pop("extend", None)
    if not base_name:
        return data
    base_path = (path.parent / str(base_name)).resolve()
    if not base_path.exists():
        raise PolicyError(f"策略继承目标不存在: {base_path}")
    base = _load_with_extends(base_path, seen)
    return _deep_merge(base, data)


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    out = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _deep_merge(out[key], value)
        else:
            out[key] = value
    return out
