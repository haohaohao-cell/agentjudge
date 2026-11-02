"""技能体检（Say-vs-Do 言行一致性）。

上架/装载前，把文档声称的能力与代码实测的行为逐维对照，生成可机读合约：

    agentjudge skill inspect examples/skills/note-taker
"""

from __future__ import annotations

from .behavior import Evidence, scan_directory, scan_file
from .claims import (
    CAPABILITIES,
    UNDECLARED_SEVERITY,
    Claim,
    capability_label,
    declared_capabilities,
    parse_claims,
)
from .report import CapabilityRow, SkillReport, inspect_skill, write_contract

__all__ = [
    "CAPABILITIES",
    "UNDECLARED_SEVERITY",
    "CapabilityRow",
    "Claim",
    "Evidence",
    "SkillReport",
    "capability_label",
    "declared_capabilities",
    "inspect_skill",
    "parse_claims",
    "scan_directory",
    "scan_file",
    "write_contract",
]
