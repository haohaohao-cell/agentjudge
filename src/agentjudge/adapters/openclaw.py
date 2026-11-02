"""OpenClaw / pointer 插件适配。

OpenClaw 的工具执行有 before/after 两个钩子；本插件注册到钩子上即可实现
“执行前裁决、执行后复核”，对被监督方零侵入。

典型接法（伪代码）::

    plugin = PointerPlugin(judge)
    agent.register_hook("tool.before", plugin.before_tool_call)
    agent.register_hook("tool.after", plugin.after_tool_result)
"""

from __future__ import annotations

from typing import Any, Callable

from ..judge import Judge
from ..types import Action, Decision, ToolCall


class PointerPlugin:
    name = "agentjudge-pointer"

    def __init__(self, judge: Judge, *, session_key: str = "session_id", default_session: str = "openclaw"):
        self.judge = judge
        self.session_key = session_key
        self.default_session = default_session

    # -- 钩子 -------------------------------------------------------------
    def before_tool_call(self, event: dict[str, Any]) -> dict[str, Any]:
        """返回 ``{"allow": bool, "decision": {...}}``；拒绝时被监督方不得执行。"""
        call = self._to_call(event)
        decision = self.judge.intercept(call)
        allowed = decision.effective_action is Action.ALLOW
        event.setdefault("meta", {})["agentjudge_decision_id"] = decision.decision_id
        event["meta"]["agentjudge_call_id"] = call.call_id
        return {
            "allow": allowed,
            "action": decision.effective_action.value,
            "reason": decision.explanation,
            "decision": decision.to_dict(),
            "call_id": call.call_id,
        }

    def after_tool_result(self, event: dict[str, Any]) -> dict[str, Any]:
        """登记返回值并做结果侧复核（读取即隔离）。"""
        call = self._to_call(event)
        call.call_id = str(event.get("meta", {}).get("agentjudge_call_id") or call.call_id)
        result = event.get("result", "")
        review = self.judge.observe(call, _render(result))
        return {
            "allow": not review.quarantined,
            "quarantined": review.quarantined,
            "reason": review.reason,
            "labels": review.labels,
        }

    def install(self, register: Callable[[str, Callable[..., Any]], Any]) -> None:
        """把钩子注册到宿主；``register(hook_name, fn)`` 由宿主提供。"""
        register("tool.before", self.before_tool_call)
        register("tool.after", self.after_tool_result)

    # -- 转换 -------------------------------------------------------------
    def _to_call(self, event: dict[str, Any]) -> ToolCall:
        meta = dict(event.get("meta") or {})
        if event.get("skill"):
            meta.setdefault("skill", event["skill"])
        if event.get("kind"):
            meta.setdefault("kind", event["kind"])
        args = event.get("args")
        if args is None:
            args = event.get("arguments") or {}
        return ToolCall(
            tool=str(event.get("tool") or event.get("name") or "unknown"),
            args=dict(args) if isinstance(args, dict) else {"value": args},
            session_id=str(event.get(self.session_key) or event.get("session") or self.default_session),
            agent_id=str(event.get("agent_id") or "openclaw"),
            meta=meta,
        )


def _render(result: Any) -> str:
    if isinstance(result, (bytes, bytearray)):
        return bytes(result).decode("utf-8", errors="replace")
    if isinstance(result, str):
        return result
    if result is None:
        return ""
    return str(result)


def as_middleware(plugin: PointerPlugin) -> Callable[[dict[str, Any]], dict[str, Any]]:
    """把插件包装成单个 middleware 函数，便于通用框架接入。"""
    return plugin.before_tool_call


__all__ = ["PointerPlugin", "as_middleware", "Decision"]
