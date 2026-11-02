"""策略回归守护。

把一次评测的结论固化成基线文件（``datasets/baseline.json``），CI 与本地改规则后
用 ``--check`` 比对：

* 攻击场景从通过变失败 → 失败
* ASR 上升 → 失败
* 新增误报用例（之前放行、现在被拦）→ 失败
* FPR 超过「基线 + 容差」→ 失败
* 场景由失败变通过 / 误报消失 → 警告（提示更新基线）

设计取向：**任何行为变化都要显式更新基线**。这样改一条正则导致误伤时，
CI 会红，必须有人确认并提交新的 baseline，而不是悄悄漂移。
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .utils import utc_now_iso

SCHEMA = 1
DEFAULT_TOLERANCE = 0.02


@dataclass(slots=True)
class RegressionResult:
    ok: bool
    failures: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    current: dict[str, float] = field(default_factory=dict)
    baseline: dict[str, float] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "failures": self.failures,
            "warnings": self.warnings,
            "current": self.current,
            "baseline": self.baseline,
        }


def baseline_from_report(report: dict[str, Any], *, tolerance: float = DEFAULT_TOLERANCE) -> dict[str, Any]:
    """从 ``run_evaluation`` 的报告生成基线。"""
    attacks = report.get("attacks") or {}
    benign = report.get("benign") or {}
    scenarios = {
        str(item.get("id")): ("pass" if item.get("passed") else "fail")
        for item in report.get("scenarios") or []
    }
    blocked_ids = sorted(
        str(item.get("id")) for item in (benign.get("failures") or []) if item.get("id")
    )
    return {
        "schema": SCHEMA,
        "generated_at": utc_now_iso(),
        "policy": report.get("policy", ""),
        "tolerance": round(float(tolerance), 4),
        "attacks": {
            "total": int(attacks.get("total") or 0),
            "intercepted": int(attacks.get("intercepted") or 0),
            "asr": float(attacks.get("asr") or 0.0),
        },
        "benign": {
            "total": int(benign.get("total") or 0),
            "fpr": float(benign.get("fpr") or 0.0),
            "completion": float(benign.get("completion") or 0.0),
            "blocked_ids": blocked_ids,
        },
        "scenarios": scenarios,
    }


def write_baseline(path: str | Path, baseline: dict[str, Any]) -> Path:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(baseline, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return target


def load_baseline(path: str | Path) -> dict[str, Any]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict) or "scenarios" not in data or "benign" not in data:
        raise ValueError(f"基线文件结构不合法: {path}")
    return data


def compare_report(
    report: dict[str, Any],
    baseline: dict[str, Any],
    *,
    tolerance: float | None = None,
) -> RegressionResult:
    tol = float(tolerance if tolerance is not None else baseline.get("tolerance", DEFAULT_TOLERANCE))
    result = RegressionResult(ok=True)

    attacks = report.get("attacks") or {}
    benign = report.get("benign") or {}
    base_attacks = baseline.get("attacks") or {}
    base_benign = baseline.get("benign") or {}

    result.current = {
        "asr": float(attacks.get("asr") or 0.0),
        "fpr": float(benign.get("fpr") or 0.0),
        "completion": float(benign.get("completion") or 0.0),
        "passed": float(sum(1 for s in report.get("scenarios") or [] if s.get("passed"))),
    }
    result.baseline = {
        "asr": float(base_attacks.get("asr") or 0.0),
        "fpr": float(base_benign.get("fpr") or 0.0),
        "completion": float(base_benign.get("completion") or 0.0),
        "passed": float(sum(1 for v in (baseline.get("scenarios") or {}).values() if v == "pass")),
    }

    # 1) 场景级别回归
    current_scenarios = {
        str(item.get("id")): ("pass" if item.get("passed") else "fail")
        for item in report.get("scenarios") or []
    }
    for sid, expected in (baseline.get("scenarios") or {}).items():
        now = current_scenarios.get(sid)
        if now is None:
            result.warnings.append(f"场景 {sid} 已不在当前数据集中")
        elif expected == "pass" and now != "pass":
            result.failures.append(f"场景 {sid} 由通过变为失败")
        elif expected == "fail" and now == "pass":
            result.warnings.append(f"场景 {sid} 由失败转为通过（可更新基线）")

    # 2) ASR 不能上升
    if result.current["asr"] > result.baseline["asr"] + 1e-9:
        result.failures.append(
            f"ASR 上升：{result.baseline['asr']:.1%} → {result.current['asr']:.1%}"
        )

    # 3) FPR 不能超出容差
    if result.current["fpr"] > result.baseline["fpr"] + tol + 1e-9:
        result.failures.append(
            f"误报率超出容差：{result.baseline['fpr']:.1%} → {result.current['fpr']:.1%}"
            f"（容差 {tol:.1%}）"
        )

    # 4) 良性完成率不能跌破容差
    if result.current["completion"] < result.baseline["completion"] - tol - 1e-9:
        result.failures.append(
            f"良性任务完成率下降：{result.baseline['completion']:.1%} → {result.current['completion']:.1%}"
        )

    # 5) 新增误报必须显式确认
    base_blocked = set(str(x) for x in (base_benign.get("blocked_ids") or []))
    now_blocked = {
        str(item.get("id")) for item in (benign.get("failures") or []) if item.get("id")
    }
    new_fps = sorted(now_blocked - base_blocked)
    if new_fps:
        result.failures.append("新增误报用例：" + ", ".join(new_fps[:10]) + ("…" if len(new_fps) > 10 else ""))
    fixed = sorted(base_blocked - now_blocked)
    if fixed:
        result.warnings.append("以下用例不再被拦（可更新基线）：" + ", ".join(fixed[:10]))

    # 6) 数据集规模变化只提示
    if int(base_attacks.get("total") or 0) != int(attacks.get("total") or 0):
        result.warnings.append(
            f"攻击场景数变化：{base_attacks.get('total')} → {attacks.get('total')}"
        )
    if int(base_benign.get("total") or 0) != int(benign.get("total") or 0):
        result.warnings.append(
            f"良性语料数变化：{base_benign.get('total')} → {benign.get('total')}"
        )

    result.ok = not result.failures
    return result


def format_result(result: RegressionResult, baseline_path: str = "") -> str:
    lines = [
        "",
        f"策略回归检查：{'通过' if result.ok else '失败'}",
    ]
    if baseline_path:
        lines.append(f"  基线文件   {baseline_path}")
    lines += [
        f"  ASR        {result.baseline['asr']:.1%} → {result.current['asr']:.1%}",
        f"  FPR        {result.baseline['fpr']:.1%} → {result.current['fpr']:.1%}",
        f"  良性完成率 {result.baseline['completion']:.1%} → {result.current['completion']:.1%}",
        f"  通过场景   {int(result.baseline['passed'])} → {int(result.current['passed'])}",
    ]
    for failure in result.failures:
        lines.append(f"  ✗ {failure}")
    for warning in result.warnings:
        lines.append(f"  ! {warning}")
    if not result.failures and not result.warnings:
        lines.append("  与基线完全一致")
    lines.append("")
    return "\n".join(lines)


__all__ = [
    "SCHEMA",
    "DEFAULT_TOLERANCE",
    "RegressionResult",
    "baseline_from_report",
    "compare_report",
    "format_result",
    "load_baseline",
    "write_baseline",
]
