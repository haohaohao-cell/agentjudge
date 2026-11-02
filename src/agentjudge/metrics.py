"""运行指标：吞吐、延迟分位、规则命中排行。

只用标准库，指标随进程存在；对外通过 ``/api/v1/metrics`` 暴露。
"""

from __future__ import annotations

import collections
import threading
import time
from typing import Any

from .types import Action, Decision


class Metrics:
    def __init__(self, max_latency_samples: int = 2000) -> None:
        self._lock = threading.RLock()
        self.started_at = time.time()
        self.total = 0
        self.by_action = {"allow": 0, "deny": 0, "escalate": 0}
        self.by_guard: collections.Counter[str] = collections.Counter()
        self.by_rule: collections.Counter[str] = collections.Counter()
        self.by_tool: collections.Counter[str] = collections.Counter()
        self.latencies: collections.deque[float] = collections.deque(maxlen=max_latency_samples)
        self.fail_closed = 0
        self.quarantined = 0
        self.watcher_rounds: collections.deque[int] = collections.deque(maxlen=500)
        self.watcher_calls = 0
        self.watcher_errors = 0

    def record(self, decision: Decision) -> None:
        with self._lock:
            self.total += 1
            self.by_action[decision.action.value] = self.by_action.get(decision.action.value, 0) + 1
            self.by_tool[decision.tool] += 1
            for f in decision.findings:
                self.by_guard[f.guard] += 1
                self.by_rule[f.rule_id] += 1
            if decision.duration_ms:
                self.latencies.append(decision.duration_ms)
            if decision.fail_closed:
                self.fail_closed += 1
            if decision.quarantined:
                self.quarantined += 1
            if decision.watcher is not None:
                self.watcher_calls += 1
                self.watcher_rounds.append(decision.watcher.rounds)
                if decision.watcher.error:
                    self.watcher_errors += 1

    @staticmethod
    def _percentile(values: list[float], pct: float) -> float:
        if not values:
            return 0.0
        ordered = sorted(values)
        idx = min(len(ordered) - 1, max(0, int(round((pct / 100) * (len(ordered) - 1)))))
        return round(ordered[idx], 3)

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            lat = list(self.latencies)
            uptime = max(0.001, time.time() - self.started_at)
            return {
                "uptime_s": round(uptime, 1),
                "total_decisions": self.total,
                "by_action": dict(self.by_action),
                "deny_rate": round(self.by_action["deny"] / self.total, 4) if self.total else 0.0,
                "by_guard": dict(self.by_guard),
                "top_rules": self.by_rule.most_common(10),
                "top_tools": self.by_tool.most_common(10),
                "latency_ms": {
                    "p50": self._percentile(lat, 50),
                    "p95": self._percentile(lat, 95),
                    "p99": self._percentile(lat, 99),
                    "max": round(max(lat), 3) if lat else 0.0,
                    "samples": len(lat),
                },
                "decisions_per_min": round(self.total / uptime * 60, 2),
                "fail_closed": self.fail_closed,
                "quarantined": self.quarantined,
                "watcher": {
                    "calls": self.watcher_calls,
                    "errors": self.watcher_errors,
                    "avg_rounds": round(sum(self.watcher_rounds) / len(self.watcher_rounds), 2)
                    if self.watcher_rounds
                    else 0.0,
                },
            }


__all__ = ["Metrics"]
