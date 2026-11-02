"""MCP（Model Context Protocol）适配。

MCP 的 ``tools/call`` 正是“执行前必须裁决”的位置。把本守卫串在 MCP 客户端与
服务端之间（进程内代理或 HTTP 代理），即可在不改服务端的前提下拦截危险调用。

    guard = MCPGuard(judge, session_id="mcp-demo")
    request = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
               "params": {"name": "fs.read", "arguments": {"path": "~/.aws/credentials"}}}
    blocked = guard.before_request(request)   # 返回 JSON-RPC error（拦截）或 None
"""

from __future__ import annotations

from typing import Any

from ..judge import Judge
from ..types import Action, ToolCall

BLOCKED_CODE = -32001
QUARANTINED_CODE = -32002


class MCPGuard:
    def __init__(self, judge: Judge, *, session_id: str = "mcp", agent_id: str = "mcp-client"):
        self.judge = judge
        self.session_id = session_id
        self.agent_id = agent_id
        self._calls: dict[str, ToolCall] = {}

    def before_request(self, request: dict[str, Any]) -> dict[str, Any] | None:
        """返回 JSON-RPC error 表示拦截；返回 None 表示放行。"""
        if request.get("method") != "tools/call":
            return None
        params = request.get("params") or {}
        name = str(params.get("name") or "unknown")
        arguments = params.get("arguments") or {}
        call = ToolCall(
            tool=name,
            args=arguments if isinstance(arguments, dict) else {"value": arguments},
            session_id=self.session_id,
            agent_id=self.agent_id,
            meta={"protocol": "mcp"},
        )
        decision = self.judge.intercept(call)
        self._calls[str(request.get("id"))] = call
        if decision.effective_action is Action.ALLOW:
            return None
        return {
            "jsonrpc": "2.0",
            "id": request.get("id"),
            "error": {
                "code": BLOCKED_CODE,
                "message": f"blocked by AgentJudge: {decision.explanation}",
                "data": {
                    "decision_id": decision.decision_id,
                    "action": decision.action.value,
                    "risk": decision.risk,
                    "reasons": decision.reasons,
                },
            },
        }

    def after_response(self, request: dict[str, Any], response: dict[str, Any]) -> dict[str, Any] | None:
        """复核返回内容；若被隔离，把结果替换成 JSON-RPC error。"""
        call = self._calls.pop(str(request.get("id")), None)
        if call is None or "error" in response:
            return None
        text = _content_text(response)
        if not text:
            return None
        review = self.judge.observe(call, text)
        if not review.quarantined:
            return None
        return {
            "jsonrpc": "2.0",
            "id": request.get("id"),
            "error": {
                "code": QUARANTINED_CODE,
                "message": f"result quarantined by AgentJudge: {review.reason}",
                "data": review.to_dict(),
            },
        }


def _content_text(response: dict[str, Any]) -> str:
    result = response.get("result") or {}
    content = result.get("content") if isinstance(result, dict) else None
    if isinstance(content, list):
        parts = []
        for item in content:
            if isinstance(item, dict) and item.get("type") == "text":
                parts.append(str(item.get("text", "")))
            elif isinstance(item, str):
                parts.append(item)
        return "\n".join(parts)
    if isinstance(content, str):
        return content
    return ""


def mcp_tools_call(name: str, arguments: dict[str, Any], *, call_id: Any = 1) -> dict[str, Any]:
    """构造一个合法的 MCP tools/call 请求。"""
    return {
        "jsonrpc": "2.0",
        "id": call_id,
        "method": "tools/call",
        "params": {"name": name, "arguments": arguments},
    }


__all__ = ["MCPGuard", "mcp_tools_call", "BLOCKED_CODE", "QUARANTINED_CODE"]
