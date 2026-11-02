"""接入 SDK：把裁决嵌进函数调用，最少三行代码。

用法一（装饰器）：::

    from agentjudge import Judge
    from agentjudge.sdk import AgentGuard

    judge = Judge.from_policy("policies/default.toml")
    guard = AgentGuard(judge, session_id="ops-42")

    @guard.tool("fs.read")
    def read_file(path: str) -> str:
        return open(path).read()

用法二（动态分发，适合插件/工具路由器）：::

    result = guard.run("shell.exec", {"command": cmd}, lambda: subprocess.run(cmd, ...))
"""

from __future__ import annotations

import functools
import inspect
import threading
from typing import Any, Callable

from .errors import EscalationRequired, ResultQuarantined, ToolCallDenied
from .judge import Judge, ResultReview
from .types import Action, Decision, ToolCall


class AgentGuard:
    """带会话上下文的接入层。线程安全。"""

    def __init__(
        self,
        judge: Judge,
        *,
        session_id: str = "default",
        agent_id: str = "agent",
        on_deny: str = "raise",       # raise | return_none
        raise_on_escalate: bool = True,
        quarantine: bool = True,
    ) -> None:
        self.judge = judge
        self.session_id = session_id
        self.agent_id = agent_id
        self.on_deny = on_deny
        self.raise_on_escalate = raise_on_escalate
        self.quarantine = quarantine
        self._local = threading.local()

    # -- 上下文 -----------------------------------------------------------
    def _session(self) -> str:
        return getattr(self._local, "session_id", self.session_id)

    class _SessionCtx:
        def __init__(self, guard: AgentGuard, session_id: str, agent_id: str | None):
            self.guard = guard
            self.session_id = session_id
            self.agent_id = agent_id
            self._prev: tuple[str, str] | None = None

        def __enter__(self) -> str:
            self._prev = (self.guard._session(), self.guard.agent_id)
            self.guard._local.session_id = self.session_id
            if self.agent_id:
                self.guard.agent_id = self.agent_id
            return self.session_id

        def __exit__(self, *exc: object) -> None:
            if self._prev:
                self.guard._local.session_id, self.guard.agent_id = self._prev

    def session(self, session_id: str, agent_id: str | None = None) -> AgentGuard._SessionCtx:
        return AgentGuard._SessionCtx(self, session_id, agent_id)

    # -- 核心 -------------------------------------------------------------
    def build_call(self, tool: str, args: dict[str, Any], *, meta: dict[str, Any] | None = None) -> ToolCall:
        return ToolCall(
            tool=tool,
            args=args,
            session_id=self._session(),
            agent_id=self.agent_id,
            meta=meta or {},
        )

    def check(self, tool: str, args: dict[str, Any], *, meta: dict[str, Any] | None = None) -> Decision:
        """只裁决不执行。"""
        return self.judge.intercept(self.build_call(tool, args, meta=meta))

    def run(
        self,
        tool: str,
        args: dict[str, Any],
        executor: Callable[[], Any],
        *,
        meta: dict[str, Any] | None = None,
        render_result: Callable[[Any], str] | None = None,
    ) -> Any:
        """裁决 → 执行 → 结果复核。拒绝时按 ``on_deny`` 抛异常或返回 None。"""
        call = self.build_call(tool, args, meta=meta)
        decision = self.judge.intercept(call)
        effective = decision.effective_action
        if effective is Action.DENY:
            if self.on_deny == "return_none":
                return None
            raise ToolCallDenied(decision)
        if effective is Action.ESCALATE and self.raise_on_escalate:
            raise EscalationRequired(decision)
        result = executor()
        if self.quarantine:
            text = render_result(result) if render_result else _default_render(result)
            review = self.judge.observe(call, text)
            if review.quarantined:
                raise ResultQuarantined(call, review)
        return result

    def tool(
        self,
        name: str | None = None,
        *,
        arg_map: dict[str, str] | None = None,
        meta: dict[str, Any] | None = None,
    ) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        """装饰器：函数名默认即工具名，参数即调用参数。"""

        def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
            tool_name = name or fn.__name__
            signature = inspect.signature(fn)

            @functools.wraps(fn)
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                bound = signature.bind_partial(*args, **kwargs)
                call_args: dict[str, Any] = {}
                for key, value in bound.arguments.items():
                    call_args[(arg_map or {}).get(key, key)] = value
                call = self.build_call(tool_name, call_args, meta=meta)
                decision = self.judge.intercept(call)
                effective = decision.effective_action
                if effective is Action.DENY:
                    if self.on_deny == "return_none":
                        return None
                    raise ToolCallDenied(decision)
                if effective is Action.ESCALATE and self.raise_on_escalate:
                    raise EscalationRequired(decision)
                result = fn(*args, **kwargs)
                if self.quarantine:
                    text = _default_render(result)
                    if text:
                        review = self.judge.observe(call, text)
                        if review.quarantined:
                            raise ResultQuarantined(call, review)
                return result

            wrapper.__agentjudge_tool__ = tool_name  # type: ignore[attr-defined]
            return wrapper

        return decorator

    def observe(self, call: ToolCall, result: Any) -> ResultReview:
        text = _default_render(result)
        return self.judge.observe(call, text)


def _default_render(result: Any) -> str:
    if result is None:
        return ""
    if isinstance(result, (bytes, bytearray)):
        return bytes(result).decode("utf-8", errors="replace")
    if isinstance(result, str):
        return result
    return str(result)


__all__ = ["AgentGuard", "ResultReview"]
