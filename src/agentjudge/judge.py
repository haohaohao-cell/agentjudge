"""裁决引擎（Judge）。

一次调用经过：守卫流水线 → 风险聚合 → 语义研判（灰区）→ 裁决落库 → 更新会话状态。
所有异常路径都以“失败即拒绝”收口。
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .audit import AuditStore, ChainRecord, Keyring
from .contracts import ContractBook
from .errors import EscalationRequired, ResultQuarantined, ToolCallDenied
from .guards import Guard, GuardContext, default_pipeline
from .guards.canary import new_canary
from .guards.rules import RulesGuard
from .guards.stego import StegoGuard
from .metrics import Metrics
from .policy import Policy
from .sensitive import TaintLabel, detect_labels, has_instruction
from .session import Session, SessionStore
from .taxonomy import ToolKind, normalize_path
from .types import Action, Decision, Finding, GuardRun, Severity, ToolCall
from .utils import mask_secrets, sha256_hex, truncate
from .watcher import Watcher, build_watcher

RESULT_PREVIEW_CHARS = 1200
MAX_STORED_ARGS_CHARS = 4000


@dataclass(slots=True)
class ResultReview:
    """工具返回值复核结论。"""

    call_id: str
    step: int
    quarantined: bool = False
    reason: str = ""
    labels: list[dict[str, Any]] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    decision: Decision | None = None
    audit_seq: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "call_id": self.call_id,
            "step": self.step,
            "quarantined": self.quarantined,
            "reason": self.reason,
            "labels": self.labels,
            "findings": [f.to_dict() for f in self.findings],
            "decision_id": self.decision.decision_id if self.decision else None,
            "audit_seq": self.audit_seq,
        }


class Judge:
    """AgentJudge 的核心裁决器。线程安全（会话锁 + 审计库串行写）。"""

    def __init__(
        self,
        policy: Policy,
        *,
        store: AuditStore | None = None,
        sessions: SessionStore | None = None,
        contracts: ContractBook | None = None,
        watcher: Watcher | None = None,
        pipeline: list[Guard] | None = None,
    ) -> None:
        self.policy = policy
        self.sessions = sessions or SessionStore()
        self.contracts = contracts if contracts is not None else self._load_contracts()
        self.store = store if store is not None else self._build_store()
        self.watcher = watcher if watcher is not None else build_watcher(policy)
        self.pipeline = pipeline or default_pipeline()
        self.metrics = Metrics()
        self._calls: dict[str, ToolCall] = {}
        self._calls_lock = __import__("threading").RLock()
        self._closed = False

    # -- 构造 -------------------------------------------------------------
    @classmethod
    def from_policy(
        cls,
        path: str | Path = "policies/default.toml",
        *,
        base_dir: str | Path | None = None,
        db_path: str | Path | None = None,
        anchor_path: str | Path | None = None,
    ) -> Judge:
        policy = Policy.load(path, base_dir=base_dir)
        store: AuditStore | None = None
        if db_path is not None or anchor_path is not None:
            key_cfg = policy.audit
            store = AuditStore(
                db_path or policy.resolve(key_cfg.db_path),
                Keyring.from_env_or_file(
                    key_file=policy.resolve(key_cfg.key_file),
                    key_env=key_cfg.key_env,
                    key_id=key_cfg.key_id,
                ),
                anchor_path=anchor_path if anchor_path is not None else policy.resolve(key_cfg.anchor_path),
                seal_interval_s=key_cfg.seal_interval_s,
            )
        return cls(policy, store=store)

    def _build_store(self) -> AuditStore:
        cfg = self.policy.audit
        keyring = Keyring.from_env_or_file(
            key_file=self.policy.resolve(cfg.key_file),
            key_env=cfg.key_env,
            key_id=cfg.key_id,
        )
        return AuditStore(
            self.policy.resolve(cfg.db_path),
            keyring,
            anchor_path=self.policy.resolve(cfg.anchor_path),
            seal_interval_s=cfg.seal_interval_s,
        )

    def _load_contracts(self) -> ContractBook:
        directory = self.policy.resolve(self.policy.contracts_dir)
        workspace = self.policy.workspace_root or str(Path.cwd())
        return ContractBook.load_dir(directory, workspace)

    def reload_contracts(self) -> int:
        self.contracts = self._load_contracts()
        return len(self.contracts)

    # -- 裁决 -------------------------------------------------------------
    def intercept(self, call: ToolCall) -> Decision:
        """在副作用发生前裁决一次工具调用。"""
        started = time.perf_counter()
        session = self.sessions.get_or_create(call.session_id, call.agent_id)
        self._ensure_canary(session)
        step = int(call.step) if call.step else session.next_step()
        call.step = step

        ctx = GuardContext(
            call=call,
            session=session,
            policy=self.policy,
            contracts=self.contracts,
            step=step,
        )
        findings, runs = self._run_pipeline(ctx)
        action, risk = arbitrate(findings, self.policy)

        watcher_report = None
        if action is Action.ESCALATE and self.policy.watcher.enabled:
            watcher_report = self.watcher.investigate(
                call=call, session=session, findings=findings, contracts=self.contracts
            )
            action, risk = self._apply_watcher(action, risk, findings, watcher_report)

        decision = Decision(
            session_id=session.id,
            tool=call.tool,
            action=action,
            step=step,
            risk=risk,
            findings=findings,
            reasons=_reason_list(findings),
            fail_closed=any(f.rule_id in {"GUARD-ERROR", "WATCH-ERR"} for f in findings),
            watcher=watcher_report,
            labels=sorted({label for hit in ctx.state.get("flow_hits", []) for label in hit.labels}),
            guards=runs,
            duration_ms=(time.perf_counter() - started) * 1000.0,
            call_id=call.call_id,
            policy_version=self.policy.version_label,
            mode=self.policy.mode,
            review_status="pending" if action is Action.ESCALATE else "auto",
            explanation=_explain(action, findings, watcher_report),
        )
        session.record(decision)
        self._write_decision(decision, call, ctx)
        self._register_side_effects(session, call, decision)
        self._remember_call(call)
        self.metrics.record(decision)
        return decision

    def _run_pipeline(self, ctx: GuardContext) -> tuple[list[Finding], list[GuardRun]]:
        findings: list[Finding] = []
        runs: list[GuardRun] = []
        broken = False
        for guard in self.pipeline:
            config = self.policy.guard(guard.name)
            if not config.enabled:
                runs.append(GuardRun(guard=guard.name, skipped="disabled"))
                continue
            if broken:
                runs.append(GuardRun(guard=guard.name, skipped="guard_error"))
                continue
            t0 = time.perf_counter()
            try:
                produced = guard.check(ctx) or []
            except Exception as exc:  # noqa: BLE001 - 失败即拒绝
                elapsed = (time.perf_counter() - t0) * 1000
                runs.append(
                    GuardRun(guard=guard.name, error=f"{type(exc).__name__}: {exc}", duration_ms=elapsed)
                )
                findings.append(
                    Finding(
                        guard=guard.name,
                        rule_id="GUARD-ERROR",
                        title=f"守卫 {guard.name} 执行异常（失败即拒绝）",
                        severity=Severity.CRITICAL,
                        action=self.policy.fail_closed_action,
                        explain="守卫无法完成判定，按策略收紧权限。",
                        evidence={"guard": guard.name, "error": f"{type(exc).__name__}: {exc}"},
                        tags=["fail_closed"],
                    )
                )
                broken = True
                continue
            elapsed = (time.perf_counter() - t0) * 1000
            runs.append(GuardRun(guard=guard.name, findings=len(produced), duration_ms=elapsed))
            findings.extend(produced)
        return findings, runs

    def _apply_watcher(
        self,
        action: Action,
        risk: int,
        findings: list[Finding],
        report: Any,
    ) -> tuple[Action, int]:
        cfg = self.policy.watcher
        if report is None:
            return action, risk
        if report.error:
            if cfg.on_error == "deny":
                findings.append(
                    Finding(
                        guard="watcher",
                        rule_id="WATCH-ERR",
                        title="语义研判失败（失败即拒绝）",
                        severity=Severity.CRITICAL,
                        action=Action.DENY,
                        explain="语义研判出现异常（超时/断网/协议错误），按策略拒绝执行。",
                        evidence={"error": report.error},
                        tags=["fail_closed", "watcher"],
                    )
                )
                return Action.DENY, max(risk, 90)
            return action, risk
        if report.verdict == "deny" and report.confidence >= cfg.min_confidence:
            findings.append(
                Finding(
                    guard="watcher",
                    rule_id="WATCH-DENY",
                    title="语义研判建议拒绝",
                    severity=Severity.HIGH,
                    action=Action.DENY,
                    explain=report.summary or "语义研判判定为高风险。",
                    evidence={"confidence": report.confidence, "rounds": report.rounds},
                    tags=["watcher"],
                )
            )
            return Action.DENY, max(risk, 75)
        if (
            report.verdict == "allow"
            and report.confidence >= cfg.min_confidence
            and cfg.can_release
        ):
            findings.append(
                Finding(
                    guard="watcher",
                    rule_id="WATCH-ALLOW",
                    title="语义研判建议放行",
                    severity=Severity.INFO,
                    action=Action.ALLOW,
                    explain=report.summary or "语义研判认为风险可接受。",
                    evidence={"confidence": report.confidence, "rounds": report.rounds},
                    tags=["watcher", "release"],
                )
            )
            return Action.ALLOW, risk
        return action, risk

    # -- 结果侧复核 -------------------------------------------------------
    def observe_by_call_id(self, call_id: str, result: str) -> ResultReview | None:
        with self._calls_lock:
            call = self._calls.get(call_id)
        if call is None:
            return None
        return self.observe(call, result)

    def _remember_call(self, call: ToolCall) -> None:
        with self._calls_lock:
            self._calls[call.call_id] = call
            if len(self._calls) > 2000:
                for key in list(self._calls)[:500]:
                    self._calls.pop(key, None)

    def observe(self, call: ToolCall, result: str, *, step: int | None = None) -> ResultReview:
        """登记工具返回值；命中注入指令则“读取即隔离”。"""
        session = self.sessions.get_or_create(call.session_id, call.agent_id)
        step = int(step or call.step or (session.steps[-1].index if session.steps else 1))
        labels = detect_labels(result or "")
        session.observe(call, result or "", step=step, labels=labels)
        review = ResultReview(
            call_id=call.call_id,
            step=step,
            labels=[lab.to_dict() for lab in labels],
        )
        record = self.store.append(
            "result",
            {
                "call_id": call.call_id,
                "step": step,
                "tool": call.tool,
                "labels": [lab.key for lab in labels],
                "chars": len(result or ""),
                "sha256": sha256_hex(result or ""),
                "preview": mask_secrets((result or "")[:RESULT_PREVIEW_CHARS]),
            },
            session_id=session.id,
            tool=call.tool,
        )
        review.audit_seq = record.seq

        if not has_instruction(labels):
            return review
        rule_opts = self.policy.guard("rules").options
        if not bool(rule_opts.get("quarantine_results", True)):
            return review

        findings = RulesGuard.scan_content(self.policy, result or "")
        findings += StegoGuard.analyze_text(result or "")
        instruction_findings = [
            f
            for f in findings
            if "instruction" in f.tags or "invisible" in f.tags or f.severity.rank >= Severity.HIGH.rank
        ]
        reason = (
            "返回值含注入指令/隐藏载荷，已隔离，后续执行与外发按污染会话处理"
            if instruction_findings
            else "返回值含注入指令，已隔离"
        )
        decision = self._decision_for_call(session, call.call_id)
        if decision is not None:
            session.mark_quarantined(decision.decision_id, reason=reason, action=self.policy.fail_closed_action)
            review.decision = decision
            review.findings = instruction_findings
            review.quarantined = True
            review.reason = reason
            self.store.append(
                "revise",
                {
                    "decision_id": decision.decision_id,
                    "step": step,
                    "action": decision.action.value,
                    "quarantined": True,
                    "reason": reason,
                    "findings": [f.to_dict() for f in instruction_findings],
                    "audit_of_result_seq": record.seq,
                },
                session_id=session.id,
                action=decision.action.value,
                tool=call.tool,
            )
        else:
            review.quarantined = True
            review.reason = reason
            review.findings = instruction_findings
        return review

    # -- 人工复核 ---------------------------------------------------------
    def pending_reviews(self) -> list[Decision]:
        out: list[Decision] = []
        for summary in self.sessions.list(limit=200):
            session = self.sessions.get(summary.session_id)
            if session is None:
                continue
            out.extend(session.pending_reviews())
        return out

    def review(
        self,
        decision_id: str,
        *,
        approve: bool,
        reviewer: str = "analyst",
        note: str = "",
    ) -> Decision | None:
        decision = self._find_decision(decision_id)
        if decision is None:
            return None
        decision.review_status = "approved" if approve else "rejected"
        decision.reviewed_by = reviewer
        decision.reviewed_at = time.time()
        decision.review_note = note
        self.store.append(
            "review",
            {
                "decision_id": decision.decision_id,
                "action": decision.action.value,
                "review_status": decision.review_status,
                "reviewer": reviewer,
                "note": note,
                "tool": decision.tool,
                "step": decision.step,
            },
            session_id=decision.session_id,
            action=decision.action.value,
            tool=decision.tool,
        )
        return decision

    # -- 查询 -------------------------------------------------------------
    def timeline(self, session_id: str) -> dict[str, Any] | None:
        session = self.sessions.get(session_id)
        return session.to_dict() if session else None

    def decision(self, decision_id: str) -> Decision | None:
        return self._find_decision(decision_id)

    def call_info(self, call_id: str | None) -> dict[str, Any] | None:
        """返回某次调用的脱敏参数（供工作台展示）。"""
        if not call_id:
            return None
        with self._calls_lock:
            call = self._calls.get(call_id)
        if call is None:
            return None
        return {
            "tool": call.tool,
            "args": _mask_args(call.args),
            "skill": call.skill,
            "content_preview": truncate(call.content or "", 400),
        }

    def verify(self) -> Any:
        return self.store.verify()

    def seal(self, *, force: bool = True) -> Any:
        return self.store.seal(force=force)

    def stats(self) -> dict[str, Any]:
        return {
            "store": self.store.stats(),
            "metrics": self.metrics.snapshot(),
            "sessions": len(self.sessions),
            "policy": self.policy.version_label,
            "mode": self.policy.mode,
            "watcher": self.watcher.provider,
            "contracts": len(self.contracts),
        }

    def hydrate(self, limit: int = 1000) -> int:
        """从审计链回放会话，使服务重启后仍能看到历史并继续污点追踪。"""
        records = self.store.records(limit=limit, kind="decision", descending=True)
        payloads = [r.to_dict() for r in reversed(records)]
        return self.sessions.hydrate_from_records(payloads)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            self.store.close()
        except Exception:  # noqa: BLE001 - 关闭阶段不再抛错
            pass

    def __enter__(self) -> Judge:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    # -- 内部 -------------------------------------------------------------
    def _ensure_canary(self, session: Session) -> None:
        if session.canaries:
            return
        cfg = self.policy.guard("canary")
        if not cfg.enabled:
            return
        if bool(cfg.get("auto_canary", True)):
            session.register_canary(new_canary(), "会话自动蜜标")

    def _decision_for_call(self, session: Session, call_id: str) -> Decision | None:
        for decision in session.decisions.values():
            if decision.call_id == call_id:
                return decision
        return None

    def _find_decision(self, decision_id: str) -> Decision | None:
        for summary in self.sessions.list(limit=500):
            session = self.sessions.get(summary.session_id)
            if session and decision_id in session.decisions:
                return session.decisions[decision_id]
        return None

    def _write_decision(self, decision: Decision, call: ToolCall, ctx: GuardContext) -> None:
        payload = {
            "decision": decision.to_dict(),
            "call": {
                "tool": call.tool,
                "args": _mask_args(call.args),
                "args_sha256": sha256_hex(str(sorted(call.args.items()))),
                "skill": call.skill,
                "agent_id": call.agent_id,
                "step": decision.step,
            },
        }
        record: ChainRecord = self.store.append(
            "decision",
            payload,
            session_id=decision.session_id,
            action=decision.action.value,
            tool=call.tool,
        )
        decision.audit_seq = record.seq  # type: ignore[attr-defined]
        hits = ctx.state.get("flow_hits") or []
        if hits:
            self.store.append(
                "flow_edge",
                {
                    "decision_id": decision.decision_id,
                    "step": decision.step,
                    "tool": call.tool,
                    "edges": [hit.to_dict() for hit in hits],
                },
                session_id=decision.session_id,
                tool=call.tool,
            )

    def _register_side_effects(self, session: Session, call: ToolCall, decision: Decision) -> None:
        """登记副作用：写入路径（用于“写了就执行”检测）与敏感参数（污点源）。"""
        if decision.action is not Action.ALLOW:
            return
        kind = _kind_of(call)
        if kind is ToolKind.FS_WRITE and call.path:
            session.written_paths.add(normalize_path(call.path))
        if kind is ToolKind.SHELL:
            for target in _redirect_targets(call.command):
                session.written_paths.add(normalize_path(target))
        text = call.all_text()
        labels = [lab for lab in detect_labels(text) if lab.category in {"credential", "secret", "canary", "pii"}]
        if labels:
            # 敏感数据已经进入智能体上下文：登记为污点源，后续外发即命中数据流守卫
            session.observe(call, text, step=decision.step, labels=labels)

    # -- SDK 便捷方法 -----------------------------------------------------
    def guard_call(self, call: ToolCall) -> Decision:
        """裁决并在拒绝/需复核时抛出异常（供装饰器使用）。"""
        decision = self.intercept(call)
        effective = decision.effective_action
        if effective is Action.DENY:
            raise ToolCallDenied(decision)
        if effective is Action.ESCALATE:
            raise EscalationRequired(decision)
        return decision

    def guard_result(self, call: ToolCall, result: str) -> ResultReview:
        review = self.observe(call, result)
        if review.quarantined:
            raise ResultQuarantined(call, review)
        return review


# ---------------------------------------------------------------------------
# 纯函数：风险聚合与解释
# ---------------------------------------------------------------------------
def arbitrate(findings: list[Finding], policy: Policy) -> tuple[Action, int]:
    """把命中项聚合为动作与风险分。

    * 只有“会干预”的命中项（action != allow）参与聚合与计分，
      纯记录型命中（如敏感数据落盘）不会累积风险；
    * 风险阈值只能“收紧”动作（转人工 → 拒绝），不能放宽。
    """
    actionable = [f for f in findings if f.action is not Action.ALLOW]
    if not actionable:
        return Action.ALLOW, 0
    risk = min(100, sum(f.severity.weight for f in actionable) + 5 * max(0, len(actionable) - 1))
    action = Action.strictest([f.action for f in actionable])
    if action is Action.ESCALATE and risk >= policy.thresholds["deny_at"]:
        action = Action.DENY
    return action, risk


def _reason_list(findings: list[Finding]) -> list[dict[str, Any]]:
    out = []
    for f in sorted(findings, key=lambda x: (x.severity.rank, x.action.rank), reverse=True):
        if f.action is Action.ALLOW:
            continue
        out.append(
            {
                "rule_id": f.rule_id,
                "guard": f.guard,
                "title": f.title,
                "severity": f.severity.value,
                "action": f.action.value,
                "explain": f.explain,
            }
        )
    return out


def _explain(action: Action, findings: list[Finding], watcher: Any) -> str:
    actionable = [f for f in findings if f.action is not Action.ALLOW]
    if not actionable:
        base = "未命中任何守卫，放行。"
        if watcher is not None and watcher.verdict == "allow":
            base = f"为避免误伤，语义研判确认放行（置信度 {watcher.confidence:.2f}）。"
        return base
    head = "；".join(f"{f.rule_id} {f.title}" for f in actionable[:3])
    tail = ""
    if watcher is not None:
        tail = f" 语义研判：{watcher.verdict}（{watcher.confidence:.2f}）"
    return f"{action.value}：{head}{tail}"


def _mask_args(args: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in args.items():
        if isinstance(value, str):
            masked = mask_secrets(truncate(value, MAX_STORED_ARGS_CHARS))
            out[key] = masked
        elif isinstance(value, (int, float, bool)) or value is None:
            out[key] = value
        else:
            out[key] = truncate(str(value), 500)
    return out


def _kind_of(call: ToolCall) -> ToolKind:
    from .taxonomy import classify_tool

    return classify_tool(call.tool, call.args, call.meta)


def _redirect_targets(command: str) -> list[str]:
    import re

    targets = []
    for match in re.finditer(r"(?<![0-9])>{1,2}\s*([^\s|&;<>]+)", command or ""):
        targets.append(match.group(1).strip("'\""))
    return [t for t in targets if t]
