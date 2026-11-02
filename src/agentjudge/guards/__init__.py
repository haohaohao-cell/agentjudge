"""守卫注册表与流水线顺序。

顺序即优先级：越快、越确定的守卫越靠前，命中致命项立即短路，
把延迟留给后面的语义研判。
"""

from __future__ import annotations

from .base import Guard, GuardContext
from .canary import CanaryGuard
from .contract import ContractGuard
from .dataflow import DataFlowGuard
from .rules import RulesGuard
from .stego import StegoGuard

__all__ = [
    "Guard",
    "GuardContext",
    "CanaryGuard",
    "StegoGuard",
    "ContractGuard",
    "RulesGuard",
    "DataFlowGuard",
    "default_pipeline",
    "GUARD_NAMES",
]

GUARD_NAMES = ("canary", "stego", "contract", "rules", "dataflow")


def default_pipeline() -> list[Guard]:
    """确定性守卫的默认顺序。"""
    return [
        CanaryGuard(),
        StegoGuard(),
        ContractGuard(),
        RulesGuard(),
        DataFlowGuard(),
    ]
