"""守卫基类与公共上下文。"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from ..contracts import ContractBook
from ..policy import Policy
from ..session import Session
from ..taxonomy import Sink, ToolKind, classify_tool, sink_of
from ..types import Action, Finding, Severity, ToolCall
from ..utils import mask_secrets, truncate


@dataclass(slots=True)
class GuardContext:
    """一次守卫检查所需的全部上下文。"""

    call: ToolCall
    session: Session
    policy: Policy
    contracts: ContractBook
    step: int
    options: dict[str, Any] = field(default_factory=dict)
    #: 守卫之间共享的计算结果（如数据流边），避免重复传播。
    state: dict[str, Any] = field(default_factory=dict)

    @property
    def tool_kind(self) -> ToolKind:
        return classify_tool(self.call.tool, self.call.args, self.call.meta)

    @property
    def sink(self) -> Sink:
        net = self.policy.network
        return sink_of(self.call, net.allow_hosts, net.internal_hosts)

    def blobs(self) -> dict[str, str]:
        return self.call.text_blobs()

    def text(self) -> str:
        return self.call.all_text()

    def option(self, key: str, default: Any = None) -> Any:
        return self.options.get(key, default)


class Guard(ABC):
    """守卫接口：只做判定，不做决策聚合。"""

    name: str = "guard"
    description: str = ""

    @abstractmethod
    def check(self, ctx: GuardContext) -> list[Finding]:
        """返回命中项；无命中返回空列表。异常由引擎按失败即拒绝处理。"""

    def enabled(self, ctx: GuardContext) -> bool:  # pragma: no cover - 默认启用
        return ctx.policy.guard(self.name).enabled


def finding(
    guard: str,
    rule_id: str,
    title: str,
    *,
    severity: Severity = Severity.HIGH,
    action: Action = Action.DENY,
    explain: str = "",
    evidence: dict[str, Any] | None = None,
    tags: list[str] | None = None,
) -> Finding:
    return Finding(
        guard=guard,
        rule_id=rule_id,
        title=title,
        severity=severity,
        action=action,
        explain=explain,
        evidence=evidence or {},
        tags=tags or [],
    )


def safe_evidence(**kwargs: Any) -> dict[str, Any]:
    """构造可展示的证据：长文本截断、密钥脱敏。"""
    out: dict[str, Any] = {}
    for key, value in kwargs.items():
        if isinstance(value, str):
            out[key] = mask_secrets(truncate(value, 300))
        else:
            out[key] = value
    return out
