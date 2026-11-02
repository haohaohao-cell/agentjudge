"""AgentJudge —— 智能体工具调用的实时审计与拦截系统。

公开入口::

    from agentjudge import Judge, ToolCall, Action

    judge = Judge.from_policy("policies/default.toml")
    decision = judge.intercept(ToolCall(session_id="s1", tool="shell.exec",
                                        args={"command": "rm -rf ~"}))
    assert decision.action is Action.DENY
"""

from __future__ import annotations

from .types import (
    Action,
    Decision,
    Finding,
    GuardRun,
    SessionSummary,
    Severity,
    ToolCall,
    TraceStep,
    WatcherReport,
)
from .version import __version__

__all__ = [
    "Action",
    "Decision",
    "Finding",
    "GuardRun",
    "SessionSummary",
    "Severity",
    "ToolCall",
    "TraceStep",
    "WatcherReport",
    "__version__",
    "Judge",
    "ToolCallDenied",
    "EscalationRequired",
    "ResultQuarantined",
]


def __getattr__(name: str):
    """延迟导入，避免循环依赖。"""
    if name == "Judge":
        from .judge import Judge

        return Judge
    if name in {"ToolCallDenied", "EscalationRequired", "ResultQuarantined"}:
        from .errors import EscalationRequired, ResultQuarantined, ToolCallDenied

        return {
            "ToolCallDenied": ToolCallDenied,
            "EscalationRequired": EscalationRequired,
            "ResultQuarantined": ResultQuarantined,
        }[name]
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
