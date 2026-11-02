"""核心数据模型。

所有对外可序列化的结构都提供 ``to_dict()``，字段名保持稳定——
审计链、HTTP API 和工作台都依赖这些字段名。
"""

from __future__ import annotations

import hashlib
import json
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


def _new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:16]}"


def _now() -> float:
    return time.time()


class Action(str, Enum):
    """三态裁决。刻意只有三种：放行、拒绝、转人工。"""

    ALLOW = "allow"
    DENY = "deny"
    ESCALATE = "escalate"

    @property
    def rank(self) -> int:
        return {"allow": 0, "escalate": 1, "deny": 2}[self.value]

    @classmethod
    def strictest(cls, actions: list[Action]) -> Action:
        return max(actions, key=lambda a: a.rank) if actions else cls.ALLOW


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def weight(self) -> int:
        return {"info": 0, "low": 10, "medium": 30, "high": 60, "critical": 100}[self.value]

    @property
    def rank(self) -> int:
        return {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}[self.value]


@dataclass(slots=True)
class ToolCall:
    """一次待裁决的工具调用（发生在副作用之前）。"""

    tool: str
    args: dict[str, Any] = field(default_factory=dict)
    session_id: str = "default"
    agent_id: str = "default"
    step: int | None = None
    call_id: str = field(default_factory=lambda: _new_id("call"))
    ts: float = field(default_factory=_now)
    #: 读取类工具返回的文本内容（可选）。用于结果侧复核（读取即隔离）。
    content: str | None = None
    #: 附加元数据：skill 名、mcp server、来源渠道、原始请求等。
    meta: dict[str, Any] = field(default_factory=dict)

    # -- 便捷访问 ---------------------------------------------------------
    def arg(self, *names: str, default: Any = None) -> Any:
        for n in names:
            if n in self.args and self.args[n] is not None:
                return self.args[n]
        return default

    @property
    def command(self) -> str:
        return str(self.arg("command", "cmd", "script", default="") or "")

    @property
    def path(self) -> str:
        return str(self.arg("path", "file", "filename", "target", default="") or "")

    @property
    def url(self) -> str:
        return str(self.arg("url", "endpoint", "uri", default="") or "")

    @property
    def skill(self) -> str:
        return str(self.meta.get("skill") or self.arg("skill", default="") or "")

    def text_blobs(self) -> dict[str, str]:
        """把调用拍平成 ``目标名 -> 文本``，供规则正则统一匹配。"""
        blobs: dict[str, str] = {"tool": self.tool}
        if self.command:
            blobs["command"] = self.command
        if self.path:
            blobs["path"] = self.path
        if self.url:
            blobs["url"] = self.url
        for key, value in self.args.items():
            if isinstance(value, str):
                blobs[f"arg.{key}"] = value
            elif isinstance(value, (int, float, bool)):
                blobs[f"arg.{key}"] = str(value)
            else:
                blobs[f"arg.{key}"] = json.dumps(value, ensure_ascii=False, default=str)
        if self.content:
            blobs["content"] = self.content
        if self.meta:
            blobs["meta"] = json.dumps(self.meta, ensure_ascii=False, default=str)
        return blobs

    def all_text(self) -> str:
        return "\n".join(self.text_blobs().values())

    def signature(self) -> str:
        payload = json.dumps(
            {"tool": self.tool, "args": self.args}, sort_keys=True, ensure_ascii=False, default=str
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        return {
            "call_id": self.call_id,
            "session_id": self.session_id,
            "agent_id": self.agent_id,
            "step": self.step,
            "tool": self.tool,
            "args": self.args,
            "ts": self.ts,
            "content": self.content,
            "meta": self.meta,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ToolCall:
        known = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        payload = {k: v for k, v in data.items() if k in known}
        payload.setdefault("tool", "")
        return cls(**payload)


@dataclass(slots=True)
class Finding:
    """单条守卫判定结果。"""

    guard: str
    rule_id: str
    title: str
    severity: Severity = Severity.MEDIUM
    action: Action = Action.DENY
    explain: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "guard": self.guard,
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.value,
            "action": self.action.value,
            "explain": self.explain,
            "evidence": self.evidence,
            "tags": self.tags,
        }


@dataclass(slots=True)
class GuardRun:
    """守卫执行痕迹（用于可解释性与性能观测）。"""

    guard: str
    findings: int = 0
    duration_ms: float = 0.0
    error: str | None = None
    skipped: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "guard": self.guard,
            "findings": self.findings,
            "duration_ms": round(self.duration_ms, 3),
            "error": self.error,
            "skipped": self.skipped,
        }


@dataclass(slots=True)
class WatcherReport:
    """语义研判（Watcher）的调查结论。"""

    verdict: str = "abstain"  # allow | deny | abstain
    confidence: float = 0.0
    rounds: int = 0
    summary: str = ""
    evidence: list[dict[str, Any]] = field(default_factory=list)
    provider: str = "none"
    error: str | None = None
    duration_ms: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict,
            "confidence": round(self.confidence, 3),
            "rounds": self.rounds,
            "summary": self.summary,
            "evidence": self.evidence,
            "provider": self.provider,
            "error": self.error,
            "duration_ms": round(self.duration_ms, 2),
        }


@dataclass(slots=True)
class Decision:
    """一次完整裁决。"""

    session_id: str
    tool: str
    action: Action
    step: int = 0
    decision_id: str = field(default_factory=lambda: _new_id("dec"))
    risk: int = 0
    findings: list[Finding] = field(default_factory=list)
    reasons: list[dict[str, Any]] = field(default_factory=list)
    fail_closed: bool = False
    quarantined: bool = False
    watcher: WatcherReport | None = None
    labels: list[str] = field(default_factory=list)
    guards: list[GuardRun] = field(default_factory=list)
    duration_ms: float = 0.0
    ts: float = field(default_factory=_now)
    call_id: str | None = None
    policy_version: str = "unknown"
    mode: str = "enforce"
    review_status: str = "auto"  # auto | pending | approved | rejected
    reviewed_by: str | None = None
    reviewed_at: float | None = None
    review_note: str | None = None
    explanation: str = ""
    audit_seq: int | None = None

    @property
    def effective_action(self) -> Action:
        """实际生效的动作：含人工复核结论、隔离与监控模式。"""
        if self.mode == "monitor":
            return Action.ALLOW
        if self.review_status == "approved":
            return Action.ALLOW
        if self.review_status == "rejected" or self.quarantined:
            return Action.DENY
        return self.action

    @property
    def allowed(self) -> bool:
        return self.effective_action is Action.ALLOW

    @property
    def blocked(self) -> bool:
        return not self.allowed

    @property
    def would_block(self) -> bool:
        """监控模式下仍然记录“本应拦截”的事实。"""
        return self.action is Action.DENY or self.quarantined

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision_id": self.decision_id,
            "call_id": self.call_id,
            "session_id": self.session_id,
            "step": self.step,
            "tool": self.tool,
            "action": self.action.value,
            "risk": self.risk,
            "findings": [f.to_dict() for f in self.findings],
            "reasons": self.reasons,
            "fail_closed": self.fail_closed,
            "quarantined": self.quarantined,
            "watcher": self.watcher.to_dict() if self.watcher else None,
            "labels": self.labels,
            "guards": [g.to_dict() for g in self.guards],
            "duration_ms": round(self.duration_ms, 3),
            "ts": self.ts,
            "policy_version": self.policy_version,
            "mode": self.mode,
            "review_status": self.review_status,
            "reviewed_by": self.reviewed_by,
            "reviewed_at": self.reviewed_at,
            "review_note": self.review_note,
            "explanation": self.explanation,
            "audit_seq": self.audit_seq,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Decision:
        findings = [
            Finding(
                guard=f.get("guard", ""),
                rule_id=f.get("rule_id", ""),
                title=f.get("title", ""),
                severity=Severity(f.get("severity", "medium")),
                action=Action(f.get("action", "deny")),
                explain=f.get("explain", ""),
                evidence=f.get("evidence", {}),
                tags=f.get("tags", []),
            )
            for f in data.get("findings", [])
        ]
        watcher = data.get("watcher")
        return cls(
            session_id=data.get("session_id", ""),
            tool=data.get("tool", ""),
            action=Action(data.get("action", "allow")),
            step=int(data.get("step") or 0),
            decision_id=data.get("decision_id") or _new_id("dec"),
            risk=int(data.get("risk") or 0),
            findings=findings,
            reasons=data.get("reasons", []),
            fail_closed=bool(data.get("fail_closed")),
            quarantined=bool(data.get("quarantined")),
            watcher=WatcherReport(**watcher) if isinstance(watcher, dict) else None,
            labels=data.get("labels", []),
            duration_ms=float(data.get("duration_ms") or 0.0),
            ts=float(data.get("ts") or _now()),
            call_id=data.get("call_id"),
            policy_version=data.get("policy_version", "unknown"),
            mode=data.get("mode", "enforce"),
            review_status=data.get("review_status", "auto"),
            reviewed_by=data.get("reviewed_by"),
            reviewed_at=data.get("reviewed_at"),
            review_note=data.get("review_note"),
            explanation=data.get("explanation", ""),
            audit_seq=data.get("audit_seq"),
        )


@dataclass(slots=True)
class TraceStep:
    """会话中的一个已裁决步骤。"""

    index: int
    tool: str
    action: Action
    risk: int
    decision_id: str
    summary: str
    labels: list[str] = field(default_factory=list)
    ts: float = field(default_factory=_now)
    has_result: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "tool": self.tool,
            "action": self.action.value,
            "risk": self.risk,
            "decision_id": self.decision_id,
            "summary": self.summary,
            "labels": self.labels,
            "ts": self.ts,
            "has_result": self.has_result,
        }


@dataclass(slots=True)
class SessionSummary:
    session_id: str
    agent_id: str = "default"
    created_at: float = field(default_factory=_now)
    updated_at: float = field(default_factory=_now)
    steps: list[TraceStep] = field(default_factory=list)
    counts: dict[str, int] = field(default_factory=lambda: {"allow": 0, "deny": 0, "escalate": 0})
    max_risk: int = 0
    labels: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "agent_id": self.agent_id,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "steps": [s.to_dict() for s in self.steps],
            "counts": self.counts,
            "max_risk": self.max_risk,
            "labels": self.labels,
            "total_steps": len(self.steps),
        }
