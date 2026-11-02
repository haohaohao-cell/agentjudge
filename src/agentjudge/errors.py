"""异常类型。

设计原则：**失败即拒绝**。任何无法完成裁决的异常，都必须被引擎转换为
``DENY``/``ESCALATE``，绝不允许静默放行。
"""

from __future__ import annotations

from typing import Any


class AgentJudgeError(Exception):
    """所有 AgentJudge 异常的基类。"""


class ConfigError(AgentJudgeError):
    """策略、合约或密钥配置非法。"""


class PolicyError(ConfigError):
    """策略文件不合法（字段缺失、类型错误、引用不存在）。"""


class ContractError(ConfigError):
    """技能/工具合约不合法。"""


class AuditError(AgentJudgeError):
    """审计链读写异常。"""


class ChainBroken(AuditError):
    """审计链完整性校验失败。"""

    def __init__(self, message: str, *, seq: int | None = None, reason: str | None = None):
        super().__init__(message)
        self.seq = seq
        self.reason = reason


class GuardError(AgentJudgeError):
    """守卫内部错误（会被引擎转换为 fail-closed 裁决）。"""


class ToolCallDenied(AgentJudgeError):
    """工具调用被拒绝；SDK 装饰器抛出，调用方不得继续执行副作用。"""

    def __init__(self, decision: Any):
        self.decision = decision
        reasons = "; ".join(r.get("title", "") for r in getattr(decision, "reasons", [])[:3])
        super().__init__(f"tool call denied by AgentJudge: {reasons or 'policy'}")


class EscalationRequired(AgentJudgeError):
    """工具调用被挂起，等待人工复核；SDK 装饰器抛出。"""

    def __init__(self, decision: Any):
        self.decision = decision
        super().__init__(
            f"tool call requires human review (decision={getattr(decision, 'decision_id', '?')})"
        )


class ResultQuarantined(AgentJudgeError):
    """工具返回值被隔离（读取即隔离）：内容含注入指令或隐藏载荷。"""

    def __init__(self, call: Any, review: Any):
        self.call = call
        self.review = review
        super().__init__(
            f"tool result quarantined by AgentJudge: {getattr(call, 'tool', '?')} "
            f"({getattr(review, 'reason', 'untrusted content')})"
        )
