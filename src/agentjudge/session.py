"""会话状态、数据打标与跨步骤数据流传播。

一次会话（session）是 AgentJudge 的审计单元。每一步的返回值都会被打标，
并作为后续步骤的“数据源”；当前调用的参数若携带某标签的数据，就形成一条
``flow_edge``（数据流边），由 ``DataFlowGuard`` 判定是否危险。
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Any

from .sensitive import TaintLabel, detect_labels, has_instruction, has_sensitive
from .types import Action, Decision, SessionSummary, TraceStep, _now
from .utils import normalize_space, tokenize

MAX_ARTIFACT_CHARS = 64_000


@dataclass(slots=True)
class Artifact:
    """某一步产生的数据（工具返回值），携带标签。"""

    step: int
    tool: str
    call_id: str
    text: str
    labels: list[TaintLabel] = field(default_factory=list)
    quarantined: bool = False
    ts: float = field(default_factory=_now)
    tokens: set[str] = field(default_factory=set)

    def __post_init__(self) -> None:
        if not self.tokens:
            self.tokens = tokenize(self.text[:MAX_ARTIFACT_CHARS])

    @property
    def label_keys(self) -> list[str]:
        return sorted({lab.key for lab in self.labels})

    def to_dict(self) -> dict[str, Any]:
        return {
            "step": self.step,
            "tool": self.tool,
            "call_id": self.call_id,
            "labels": [lab.to_dict() for lab in self.labels],
            "quarantined": self.quarantined,
            "chars": len(self.text),
            "ts": self.ts,
        }


@dataclass(slots=True)
class FlowHit:
    """一次“数据从历史步骤流入当前调用”的命中。"""

    source_step: int
    source_tool: str
    labels: list[str]
    method: str  # exact | encoded | token | instruction
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_step": self.source_step,
            "source_tool": self.source_tool,
            "labels": self.labels,
            "method": self.method,
            "detail": self.detail,
        }


class Session:
    """一个智能体会话的完整状态。"""

    def __init__(self, session_id: str, agent_id: str = "default", *, canaries: list[str] | None = None):
        self.id = session_id
        self.agent_id = agent_id
        self.created_at = _now()
        self.updated_at = self.created_at
        self.steps: list[TraceStep] = []
        self.decisions: dict[str, Decision] = {}
        self.artifacts: list[Artifact] = []
        self.canaries: list[str] = list(canaries or [])
        self.canary_locations: dict[str, str] = {}
        self.written_paths: set[str] = set()
        self.labels: set[str] = set()
        self.max_risk = 0
        self.counts = {"allow": 0, "deny": 0, "escalate": 0}
        self.lock = threading.RLock()
        self._next_step = 1

    # -- 令牌/蜜标 --------------------------------------------------------
    def register_canary(self, token: str, location: str = "") -> None:
        if token and token not in self.canaries:
            self.canaries.append(token)
            self.canary_locations[token] = location

    def next_step(self) -> int:
        with self.lock:
            step = self._next_step
            self._next_step += 1
            return step

    # -- 记录 -------------------------------------------------------------
    def record(self, decision: Decision, *, summary: str = "") -> TraceStep:
        with self.lock:
            entry = TraceStep(
                index=decision.step,
                tool=decision.tool,
                action=decision.action,
                risk=decision.risk,
                decision_id=decision.decision_id,
                summary=summary or self._summary_of(decision),
                labels=decision.labels,
                ts=decision.ts,
            )
            self.steps.append(entry)
            self.decisions[decision.decision_id] = decision
            self.counts[decision.action.value] = self.counts.get(decision.action.value, 0) + 1
            self.max_risk = max(self.max_risk, decision.risk)
            self.labels.update(decision.labels)
            self.updated_at = _now()
            return entry

    @staticmethod
    def _summary_of(decision: Decision) -> str:
        if decision.findings:
            top = max(decision.findings, key=lambda f: f.severity.rank)
            return top.title
        return f"{decision.action.value}（风险评估 {decision.risk}）"

    def observe(self, call: Any, result: str, *, step: int, labels: list[TaintLabel] | None = None) -> Artifact:
        """登记工具返回值，生成数据源。"""
        with self.lock:
            text = (result or "")[:MAX_ARTIFACT_CHARS]
            labs = labels if labels is not None else detect_labels(text)
            artifact = Artifact(
                step=step,
                tool=call.tool,
                call_id=getattr(call, "call_id", ""),
                text=text,
                labels=labs,
                tokens=tokenize(text),
            )
            self.artifacts.append(artifact)
            for lab in labs:
                self.labels.add(lab.key)
            if len(self.artifacts) > 256:  # 有界内存：保留最近 256 个数据源
                self.artifacts = self.artifacts[-256:]
            for entry in reversed(self.steps):
                if entry.index == step:
                    entry.has_result = True
                    break
            self.updated_at = _now()
            return artifact

    def mark_quarantined(self, decision_id: str, *, reason: str, action: Action = Action.DENY) -> Decision | None:
        """结果侧复核命中：把该步骤升级为隔离并拦截。"""
        with self.lock:
            decision = self.decisions.get(decision_id)
            if decision is None:
                return None
            previous = decision.action
            decision.action = action
            decision.quarantined = True
            if previous is not action:
                self.counts[previous.value] = max(0, self.counts.get(previous.value, 0) - 1)
                self.counts[action.value] = self.counts.get(action.value, 0) + 1
            for entry in self.steps:
                if entry.decision_id == decision_id:
                    entry.action = action
                    entry.labels = sorted(set(entry.labels) | {"instruction:quarantined"})
                    entry.summary = f"{entry.summary}｜已隔离：{reason}"
                    break
            self.updated_at = _now()
            return decision

    # -- 数据流传播 -------------------------------------------------------
    def propagate(self, text: str, *, decoded_views: list[str] | None = None) -> list[FlowHit]:
        """检查当前文本是否携带了历史步骤中的敏感数据。"""
        if not text or not self.artifacts:
            return []
        current_tokens = tokenize(text)
        views = [text]
        if decoded_views:
            views.extend(decoded_views)
        hits: dict[tuple[int, str], FlowHit] = {}
        for artifact in self.artifacts:
            if not artifact.labels:
                continue
            keys = artifact.label_keys
            # 1) 精确样本命中（最可靠）
            exact = [lab for lab in artifact.labels if lab.sample and lab.sample in text]
            if exact:
                hit = FlowHit(
                    source_step=artifact.step,
                    source_tool=artifact.tool,
                    labels=sorted({lab.key for lab in exact}),
                    method="exact",
                    detail=_brief(exact[0].sample),
                )
                hits[(artifact.step, "exact")] = hit
                continue
            # 2) 编码视图命中（base64/hex/URL 编码后的外泄）
            encoded_hit = self._encoded_hit(artifact, views)
            if encoded_hit:
                hits[(artifact.step, "encoded")] = encoded_hit
                continue
            # 3) 词元重叠（结构性搬运，如 JSON 重组、字段改名）
            overlap = current_tokens & artifact.tokens
            if len(overlap) >= 3 and len(overlap) / max(1, min(len(artifact.tokens), len(current_tokens))) >= 0.35:
                hits[(artifact.step, "token")] = FlowHit(
                    source_step=artifact.step,
                    source_tool=artifact.tool,
                    labels=keys,
                    method="token",
                    detail=", ".join(sorted(overlap)[:6]),
                )
        return list(hits.values())

    @staticmethod
    def _encoded_hit(artifact: Artifact, views: list[str]) -> FlowHit | None:
        import base64

        sensitive = [lab for lab in artifact.labels if lab.category in {"credential", "secret", "pii", "canary"}]
        if not sensitive:
            return None
        for lab in sensitive:
            sample = lab.sample
            if len(sample) < 6:
                continue
            variants = [
                base64.b64encode(sample.encode("utf-8")).decode("ascii"),
                base64.b64encode(sample.encode("utf-8")).decode("ascii").rstrip("="),
                sample.encode("utf-8").hex(),
            ]
            for view in views:
                for variant in variants:
                    if variant and variant in view:
                        return FlowHit(
                            source_step=artifact.step,
                            source_tool=artifact.tool,
                            labels=[lab.key],
                            method="encoded",
                            detail=f"{lab.name} 以编码形式出现",
                        )
        return None

    def instruction_sources(self) -> list[Artifact]:
        return [a for a in self.artifacts if has_instruction(a.labels)]

    def has_sensitive_context(self) -> bool:
        return any(has_sensitive(a.labels) for a in self.artifacts)

    # -- 视图 -------------------------------------------------------------
    def timeline(self) -> list[dict[str, Any]]:
        out = []
        by_step = {a.step: a for a in self.artifacts}
        for entry in self.steps:
            item = entry.to_dict()
            art = by_step.get(entry.index)
            if art is not None:
                item["artifact"] = art.to_dict()
            decision = self.decisions.get(entry.decision_id)
            if decision is not None:
                item["decision"] = decision.to_dict()
            out.append(item)
        return out

    def pending_reviews(self) -> list[Decision]:
        return [
            d
            for d in self.decisions.values()
            if d.action.value == "escalate" and d.review_status == "pending"
        ]

    def summary(self) -> SessionSummary:
        total_labels = sorted(self.labels)
        return SessionSummary(
            session_id=self.id,
            agent_id=self.agent_id,
            created_at=self.created_at,
            updated_at=self.updated_at,
            steps=list(self.steps),
            counts=dict(self.counts),
            max_risk=self.max_risk,
            labels=total_labels,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            **self.summary().to_dict(),
            "timeline": self.timeline(),
            "artifacts": [a.to_dict() for a in self.artifacts],
            "canaries": [{"token": c, "location": self.canary_locations.get(c, "")} for c in self.canaries],
            "written_paths": sorted(self.written_paths),
        }


class SessionStore:
    """进程内会话表（线程安全）。

    审计链是持久化的事实来源；会话表只承载“当前活动的数据流上下文”。
    进程重启后可由审计记录回放重建（见 ``hydrate_from_records``）。
    """

    def __init__(self) -> None:
        self._sessions: dict[str, Session] = {}
        self._lock = threading.RLock()

    def get(self, session_id: str) -> Session | None:
        with self._lock:
            return self._sessions.get(session_id)

    def get_or_create(
        self, session_id: str, agent_id: str = "default", *, canaries: list[str] | None = None
    ) -> Session:
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                session = Session(session_id, agent_id, canaries=canaries)
                self._sessions[session_id] = session
            return session

    def put(self, session: Session) -> None:
        with self._lock:
            self._sessions[session.id] = session

    def list(self, limit: int = 50) -> list[SessionSummary]:
        with self._lock:
            sessions = sorted(self._sessions.values(), key=lambda s: s.updated_at, reverse=True)
        return [s.summary() for s in sessions[:limit]]

    def remove(self, session_id: str) -> bool:
        with self._lock:
            return self._sessions.pop(session_id, None) is not None

    def clear(self) -> None:
        with self._lock:
            self._sessions.clear()

    def __len__(self) -> int:
        return len(self._sessions)

    def hydrate_from_records(self, records: list[dict[str, Any]]) -> int:
        """从审计记录回放重建会话（重启后排障用）。"""
        count = 0
        for rec in records:
            if rec.get("kind") != "decision":
                continue
            payload = rec.get("payload") or {}
            decision_data = payload.get("decision") or {}
            if not decision_data:
                continue
            try:
                decision = Decision.from_dict(decision_data)
            except Exception:  # pragma: no cover - 容忍历史格式
                continue
            session = self.get_or_create(decision.session_id)
            if decision.step and decision.step in {s.index for s in session.steps}:
                continue
            session.record(decision)
            session._next_step = max(session._next_step, decision.step + 1)
            count += 1
        return count


def _brief(text: str, limit: int = 80) -> str:
    return normalize_space(text)[:limit]


__all__ = ["Artifact", "FlowHit", "Session", "SessionStore"]
