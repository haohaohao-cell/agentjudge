"""离线评测：红队场景回放 + 良性语料误报测量。

评测复用生产裁决路径（同一个 ``Judge``），不做任何特判，因此指标可以代表
真实部署时的行为。
"""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .judge import Judge
from .types import Action, Decision, ToolCall
from .version import __version__


@dataclass(slots=True)
class ScenarioStep:
    tool: str
    args: dict[str, Any] = field(default_factory=dict)
    result: str = ""

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ScenarioStep:
        return cls(
            tool=str(data.get("tool", "")),
            args=dict(data.get("args") or {}),
            result=str(data.get("result") or ""),
        )


@dataclass(slots=True)
class Scenario:
    id: str
    name: str
    steps: list[ScenarioStep]
    description: str = ""
    tags: list[str] = field(default_factory=list)
    expect_first_interception: int | None = None
    source: str = ""

    @classmethod
    def from_dict(cls, data: dict[str, Any], *, source: str = "") -> Scenario:
        return cls(
            id=str(data.get("id", "")),
            name=str(data.get("name", "")),
            steps=[ScenarioStep.from_dict(s) for s in data.get("steps", [])],
            description=str(data.get("description", "")),
            tags=[str(t) for t in data.get("tags", [])],
            expect_first_interception=data.get("expect_first_interception"),
            source=source,
        )

    @property
    def is_attack(self) -> bool:
        return self.expect_first_interception is not None


@dataclass(slots=True)
class StepOutcome:
    index: int
    tool: str
    action: str
    effective: str
    risk: int
    rules: list[str]
    quarantined: bool = False
    intercepted: bool = False
    duration_ms: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "tool": self.tool,
            "action": self.action,
            "effective": self.effective,
            "risk": self.risk,
            "rules": self.rules,
            "quarantined": self.quarantined,
            "intercepted": self.intercepted,
            "duration_ms": round(self.duration_ms, 2),
        }


@dataclass(slots=True)
class ScenarioResult:
    id: str
    name: str
    passed: bool
    first_interception: int | None
    expected: int | None
    outcomes: list[StepOutcome] = field(default_factory=list)
    reason: str = ""
    description: str = ""
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "passed": self.passed,
            "first_interception": self.first_interception,
            "expected": self.expected,
            "reason": self.reason,
            "description": self.description,
            "tags": self.tags,
            "steps": [o.to_dict() for o in self.outcomes],
        }


@dataclass(slots=True)
class CorpusResult:
    total: int = 0
    allowed: int = 0
    blocked: int = 0
    failures: list[dict[str, Any]] = field(default_factory=list)

    @property
    def fpr(self) -> float:
        return round(self.blocked / self.total, 4) if self.total else 0.0

    @property
    def completion(self) -> float:
        return round(self.allowed / self.total, 4) if self.total else 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "total": self.total,
            "allowed": self.allowed,
            "blocked": self.blocked,
            "fpr": self.fpr,
            "completion": self.completion,
            "failures": self.failures,
        }


# ---------------------------------------------------------------------------
# 加载
# ---------------------------------------------------------------------------
def load_scenarios(directory: str | Path) -> list[Scenario]:
    root = Path(directory)
    if not root.exists():
        return []
    scenarios = []
    for path in sorted(root.glob("*.json")):
        with path.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
        scenarios.append(Scenario.from_dict(data, source=str(path)))
    return scenarios


def load_corpus(path: str | Path) -> list[dict[str, Any]]:
    p = Path(path)
    if not p.exists():
        return []
    with p.open("r", encoding="utf-8") as fh:
        data = json.load(fh)
    return data if isinstance(data, list) else []


# ---------------------------------------------------------------------------
# 执行
# ---------------------------------------------------------------------------
def _substitute(value: Any, canary: str) -> Any:
    if isinstance(value, str):
        return value.replace("{{canary}}", canary)
    if isinstance(value, dict):
        return {k: _substitute(v, canary) for k, v in value.items()}
    if isinstance(value, list):
        return [_substitute(v, canary) for v in value]
    return value


def run_scenario(judge: Judge, scenario: Scenario, *, prefix: str = "eval") -> ScenarioResult:
    session_id = f"{prefix}-{scenario.id}-{uuid.uuid4().hex[:6]}"
    session = judge.sessions.get_or_create(session_id, agent_id="eval")
    if not session.canaries:
        from .guards.canary import new_canary

        session.register_canary(new_canary(), f"场景 {scenario.id} 诱饵")
    canary = session.canaries[0]

    outcomes: list[StepOutcome] = []
    first: int | None = None
    for index, step in enumerate(scenario.steps, 1):
        args = _substitute(step.args, canary)
        call = ToolCall(
            tool=step.tool,
            args=args,
            session_id=session_id,
            agent_id="eval",
            meta={"scenario": scenario.id, "dataset": "redteam"},
        )
        decision: Decision = judge.intercept(call)
        effective = decision.effective_action
        intercepted = effective is not Action.ALLOW
        outcomes.append(
            StepOutcome(
                index=index,
                tool=step.tool,
                action=decision.action.value,
                effective=effective.value,
                risk=decision.risk,
                rules=[r["rule_id"] for r in decision.reasons],
                quarantined=decision.quarantined,
                intercepted=intercepted,
                duration_ms=decision.duration_ms,
            )
        )
        if intercepted:
            first = index
            break
        if step.result:
            review = judge.observe(call, _substitute(step.result, canary))
            if review.quarantined:
                outcomes[-1].quarantined = True
                outcomes[-1].intercepted = True
                outcomes[-1].rules = outcomes[-1].rules + ["RESULT-QUARANTINE"]
                first = index
                break

    if scenario.expect_first_interception is None:
        passed = first is None
        reason = "全程放行" if passed else f"误拦截于第 {first} 步"
    else:
        passed = first is not None and first <= int(scenario.expect_first_interception)
        if first is None:
            reason = "未被拦截（漏放）"
        elif first <= int(scenario.expect_first_interception):
            reason = f"第 {first} 步拦截（预期不晚于第 {scenario.expect_first_interception} 步）"
        else:
            reason = f"第 {first} 步才拦截，晚于预期第 {scenario.expect_first_interception} 步"

    return ScenarioResult(
        id=scenario.id,
        name=scenario.name,
        passed=passed,
        first_interception=first,
        expected=scenario.expect_first_interception,
        outcomes=outcomes,
        reason=reason,
        description=scenario.description,
        tags=scenario.tags,
    )


def run_corpus(judge: Judge, entries: list[dict[str, Any]], *, prefix: str = "corpus") -> CorpusResult:
    result = CorpusResult()
    for entry in entries:
        result.total += 1
        tool = str(entry.get("tool", ""))
        call = ToolCall(
            tool=tool,
            args=dict(entry.get("args") or {}),
            session_id=f"{prefix}-{entry.get('id', uuid.uuid4().hex[:6])}",
            agent_id="eval",
            meta={"dataset": "benign"},
        )
        decision = judge.intercept(call)
        blocked = decision.effective_action is not Action.ALLOW
        rule_ids = [r["rule_id"] for r in decision.reasons]
        if not blocked and entry.get("result"):
            review = judge.observe(call, str(entry["result"]))
            if review.quarantined:
                blocked = True
                rule_ids = rule_ids + ["RESULT-QUARANTINE"]
        if blocked:
            result.blocked += 1
            result.failures.append(
                {
                    "id": entry.get("id"),
                    "tool": tool,
                    "args": entry.get("args"),
                    "action": decision.action.value,
                    "risk": decision.risk,
                    "rules": rule_ids,
                }
            )
        else:
            result.allowed += 1
    return result


def run_evaluation(
    judge: Judge,
    scenarios: list[Scenario],
    corpus: list[dict[str, Any]],
) -> dict[str, Any]:
    started = time.perf_counter()
    results = [run_scenario(judge, s) for s in scenarios]
    corpus_result = run_corpus(judge, corpus)
    latencies = [o.duration_ms for r in results for o in r.outcomes]
    attacks = [r for r in results if r.expected is not None]
    intercepted = [r for r in attacks if r.first_interception is not None]
    missed = [r for r in attacks if r.first_interception is None]
    metrics = judge.metrics.snapshot()

    def pct(values: list[float], p: float) -> float:
        if not values:
            return 0.0
        ordered = sorted(values)
        idx = min(len(ordered) - 1, int(round((p / 100) * (len(ordered) - 1))))
        return round(ordered[idx], 3)

    report = {
        "version": __version__,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "duration_s": round(time.perf_counter() - started, 2),
        "policy": judge.policy.version_label,
        "mode": judge.policy.mode,
        "watcher": judge.watcher.provider,
        "attacks": {
            "total": len(attacks),
            "intercepted": len(intercepted),
            "missed": len(missed),
            "asr": round(len(missed) / len(attacks), 4) if attacks else 0.0,
            "pass_rate": round(sum(1 for r in attacks if r.passed) / len(attacks), 4) if attacks else 0.0,
        },
        "benign": corpus_result.to_dict(),
        "latency_ms": {"p50": pct(latencies, 50), "p95": pct(latencies, 95), "max": round(max(latencies), 3) if latencies else 0.0},
        "guards": metrics["by_guard"],
        "top_rules": metrics["top_rules"],
        "scenarios": [r.to_dict() for r in results],
    }
    return report


def report_markdown(report: dict[str, Any]) -> str:
    attacks = report["attacks"]
    benign = report["benign"]
    lines = [
        "# AgentJudge 评测报告",
        "",
        f"- 策略：`{report['policy']}`（{report['mode']}）",
        f"- 语义研判：{report['watcher']}",
        f"- 生成时间：{report['generated_at']}",
        f"- 耗时：{report['duration_s']}s",
        "",
        "## 关键指标",
        "",
        "| 指标 | 数值 |",
        "| --- | --- |",
        f"| 红队场景 | {attacks['total']} |",
        f"| 已拦截 | {attacks['intercepted']} |",
        f"| ASR（攻击成功率） | {attacks['asr'] * 100:.1f}% |",
        f"| 场景通过率 | {attacks['pass_rate'] * 100:.1f}% |",
        f"| 良性语料完成率 | {benign['completion'] * 100:.1f}% |",
        f"| 误报率 FPR | {benign['fpr'] * 100:.1f}% |",
        f"| 裁决延迟 p50 / p95 | {report['latency_ms']['p50']} / {report['latency_ms']['p95']} ms |",
        "",
        "## 场景明细",
        "",
        "| 场景 | 名称 | 结果 | 首个拦截点 | 说明 |",
        "| --- | --- | --- | --- | --- |",
    ]
    for item in report["scenarios"]:
        mark = "PASS" if item["passed"] else "FAIL"
        first = item["first_interception"] if item["first_interception"] is not None else "-"
        expected = item["expected"] if item["expected"] is not None else "放行"
        lines.append(f"| {item['id']} | {item['name']} | {mark} | {first} / {expected} | {item['reason']} |")
    if benign["failures"]:
        lines += ["", "## 误报明细", "", "| 用例 | 工具 | 命中规则 |", "| --- | --- | --- |"]
        for failure in benign["failures"]:
            lines.append(
                f"| {failure['id']} | {failure['tool']} | {', '.join(failure['rules']) or '-'} |"
            )
    return "\n".join(lines) + "\n"


__all__ = [
    "Scenario",
    "ScenarioStep",
    "ScenarioResult",
    "CorpusResult",
    "load_scenarios",
    "load_corpus",
    "run_scenario",
    "run_corpus",
    "run_evaluation",
    "report_markdown",
]
