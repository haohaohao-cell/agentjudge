"""技能体检报告：言行对照矩阵、信任评级与合约生成。"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..utils import canonical_json, utc_now_iso
from .behavior import Evidence, scan_directory
from .claims import (
    CAPABILITIES,
    UNDECLARED_SEVERITY,
    Claim,
    capability_label,
    declared_capabilities,
    denied_capabilities,
    parse_claims,
)

MANIFEST_NAMES = ("skill.json", "manifest.json", "skill.toml", "SKILL.json")
DOC_NAMES = ("SKILL.md", "README.md", "skill.md", "readme.md")

# 未声明能力的分值扣减
PENALTY = {"high": 35, "medium": 12, "low": 3}
DANGER_PENALTY = {"high": 25, "medium": 12, "low": 4}
QUARANTINE_SCORE = 55
TRUSTED_SCORE = 88


@dataclass(slots=True)
class CapabilityRow:
    key: str
    label: str
    declared: bool
    observed: bool
    denied: bool = False
    evidence: list[Evidence] = field(default_factory=list)

    @property
    def drift(self) -> str:
        if self.observed and self.denied:
            return "contradicted"
        if self.observed and not self.declared:
            return "undeclared"
        if self.declared and not self.observed:
            return "unmet"
        return "match"

    def to_dict(self) -> dict[str, Any]:
        return {
            "capability": self.key,
            "label": self.label,
            "declared": self.declared,
            "observed": self.observed,
            "denied": self.denied,
            "drift": self.drift,
            "evidence": [e.to_dict() for e in self.evidence[:4]],
        }


@dataclass(slots=True)
class SkillReport:
    path: str
    name: str
    version: str = "0.0.0"
    description: str = ""
    claims: list[Claim] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)
    matrix: list[CapabilityRow] = field(default_factory=list)
    files: list[str] = field(default_factory=list)
    score: int = 100
    trust: str = "trusted"
    generated_at: str = field(default_factory=utc_now_iso)
    fingerprint: str = ""

    # -- 派生属性 ---------------------------------------------------------
    @property
    def declared(self) -> list[str]:
        return [r.key for r in self.matrix if r.declared]

    @property
    def observed(self) -> list[str]:
        return [r.key for r in self.matrix if r.observed]

    @property
    def drift(self) -> list[dict[str, Any]]:
        rows = [r for r in self.matrix if r.drift in {"undeclared", "contradicted"}]
        return [
            {
                "capability": r.key,
                "label": r.label,
                "kind": r.drift,
                "severity": UNDECLARED_SEVERITY.get(r.key, "low"),
                "detail": (
                    f"文档未声明却实测具备“{r.label}”能力"
                    if r.drift == "undeclared"
                    else f"文档明确否认“{r.label}”，但代码实测具备"
                ),
                "evidence": [e.to_dict() for e in r.evidence[:3]],
            }
            for r in rows
        ]

    @property
    def dangers(self) -> list[dict[str, Any]]:
        return [e.to_dict() for e in self.evidence if e.kind == "danger"]

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "generated_at": self.generated_at,
            "fingerprint": self.fingerprint,
            "score": self.score,
            "trust": self.trust,
            "declared": self.declared,
            "observed": self.observed,
            "matrix": [row.to_dict() for row in self.matrix],
            "drift": self.drift,
            "dangers": self.dangers,
            "claims": [c.to_dict() for c in self.claims],
            "files": self.files,
            "summary": self.summary(),
        }

    def summary(self) -> str:
        if self.trust == "trusted":
            return "言行一致：文档声明与代码实测能力吻合。"
        if self.trust == "quarantined":
            missing = "、".join(item["label"] for item in self.drift[:4]) or "高危行为"
            return f"言行不一致：未声明却实测具备 {missing}，建议隔离。"
        missing = "、".join(item["label"] for item in self.drift[:4]) or "部分能力"
        return f"条件信任：存在未声明能力（{missing}），仅允许已声明能力运行。"

    # -- 合约 -------------------------------------------------------------
    def contract_mapping(self) -> dict[str, Any]:
        return {
            "tool": {"name": "*", "kind": "skill", "description": f"{self.name} 技能合约"},
            "skill": {
                "name": self.name,
                "status": self.trust,
                "capabilities": self.declared or self.observed,
                "declared": self.declared,
                "observed": self.observed,
                "fingerprint": self.fingerprint,
                "generated_at": self.generated_at,
                "source": self.path,
            },
        }

    def contract_toml(self) -> str:
        """生成可存档、可 diff 的技能合约。"""
        caps = ", ".join(json.dumps(x, ensure_ascii=False) for x in (self.declared or self.observed))
        declared = ", ".join(json.dumps(x) for x in self.declared)
        observed = ", ".join(json.dumps(x) for x in self.observed)
        reasons = "; ".join(f"{d['capability']}:{d['kind']}" for d in self.drift) or "none"
        return (
            "# 由 `agentjudge skill inspect` 自动生成，请勿手工编辑。\n"
            f"# 生成时间: {self.generated_at}\n"
            f"# 信任评级: {self.trust}（评分 {self.score}/100）\n"
            f"# 言行差异: {reasons}\n\n"
            "[tool]\n"
            'name = "*"\n'
            'kind = "skill"\n'
            f"description = {json.dumps(self.name + ' 技能合约', ensure_ascii=False)}\n\n"
            "[skill]\n"
            f"name = {json.dumps(self.name, ensure_ascii=False)}\n"
            f"status = {json.dumps(self.trust)}\n"
            f"capabilities = [{caps}]\n"
            f"declared = [{declared}]\n"
            f"observed = [{observed}]\n"
            f"fingerprint = {json.dumps(self.fingerprint)}\n"
            f"generated_at = {json.dumps(self.generated_at)}\n"
            f"source = {json.dumps(self.path.replace(chr(92), '/'), ensure_ascii=False)}\n"
        )


def inspect_skill(path: str | Path) -> SkillReport:
    root = Path(path)
    if not root.exists():
        raise FileNotFoundError(f"技能目录不存在: {root}")
    manifest = _read_manifest(root)
    name = str(manifest.get("name") or root.name)
    version = str(manifest.get("version") or "0.0.0")
    description = str(manifest.get("description") or "")

    doc_text = _read_docs(root)
    claims = parse_claims(doc_text, location=_doc_location(root))
    if description:
        claims += parse_claims(description, location="manifest")
    declared = declared_capabilities(claims)
    denied = denied_capabilities(claims)
    evidence = scan_directory(root)
    observed = {e.capability for e in evidence}

    matrix: list[CapabilityRow] = []
    for key, (label, _pattern) in CAPABILITIES.items():
        cap_evidence = [e for e in evidence if e.capability == key]
        matrix.append(
            CapabilityRow(
                key=key,
                label=label,
                declared=key in declared,
                observed=key in observed,
                denied=key in denied,
                evidence=cap_evidence,
            )
        )

    report = SkillReport(
        path=str(root.resolve()),
        name=name,
        version=version,
        description=description[:300],
        claims=claims,
        evidence=evidence,
        matrix=matrix,
        files=_list_files(root),
        generated_at=utc_now_iso(),
    )
    _score(report)
    report.fingerprint = _fingerprint(root, report)
    return report


# ---------------------------------------------------------------------------
# 评分与信任
# ---------------------------------------------------------------------------
def _score(report: SkillReport) -> None:
    score = 100
    hard_quarantine = False
    for row in report.matrix:
        if row.drift == "undeclared":
            score -= PENALTY.get(UNDECLARED_SEVERITY.get(row.key, "low"), 3)
            if UNDECLARED_SEVERITY.get(row.key) == "high":
                hard_quarantine = True
        elif row.drift == "contradicted":
            score -= PENALTY["high"]
            hard_quarantine = True
        elif row.drift == "unmet":
            score -= 2
    dangers = report.dangers
    if dangers:
        worst = max((d["severity"] for d in dangers), key=lambda s: {"low": 0, "medium": 1, "high": 2}.get(s, 0))
        score -= DANGER_PENALTY.get(worst, 4)
        if worst == "high":
            hard_quarantine = True
    score = max(0, min(100, score))
    report.score = score
    if hard_quarantine or score < QUARANTINE_SCORE:
        report.trust = "quarantined"
    elif score < TRUSTED_SCORE or any(row.drift == "undeclared" for row in report.matrix):
        report.trust = "conditional"
    else:
        report.trust = "trusted"


def _fingerprint(root: Path, report: SkillReport) -> str:
    h = hashlib.sha256()
    for rel in sorted(report.files):
        p = root / rel
        try:
            h.update(rel.encode("utf-8"))
            h.update(p.read_bytes()[:200_000])
        except OSError:
            continue
    h.update(canonical_json({"declared": sorted(report.declared)}).encode("utf-8"))
    return h.hexdigest()


# ---------------------------------------------------------------------------
# 文件发现
# ---------------------------------------------------------------------------
def _read_manifest(root: Path) -> dict[str, Any]:
    for candidate in root.iterdir() if root.is_dir() else []:
        if candidate.name in MANIFEST_NAMES:
            try:
                if candidate.suffix == ".json":
                    return json.loads(candidate.read_text(encoding="utf-8"))
                import tomllib

                with candidate.open("rb") as fh:
                    return tomllib.load(fh)
            except (OSError, ValueError):
                return {}
    return {}


def _read_docs(root: Path) -> str:
    chunks: list[str] = []
    for candidate in root.iterdir() if root.is_dir() else []:
        if candidate.name in DOC_NAMES and candidate.is_file():
            try:
                chunks.append(candidate.read_text(encoding="utf-8", errors="ignore")[:40_000])
            except OSError:
                continue
    return "\n".join(chunks)


def _doc_location(root: Path) -> str:
    for candidate in root.iterdir() if root.is_dir() else []:
        if candidate.name in DOC_NAMES:
            return candidate.name
    return "SKILL.md"


def _list_files(root: Path) -> list[str]:
    out: list[str] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if any(part in {".git", "node_modules", "__pycache__", "dist", "build"} for part in path.parts):
            continue
        try:
            out.append(str(path.relative_to(root)).replace("\\", "/"))
        except ValueError:
            continue
    return out[:200]


def write_contract(report: SkillReport, contracts_dir: str | Path) -> Path:
    target = Path(contracts_dir) / "skills" / f"{report.name}.toml"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(report.contract_toml(), encoding="utf-8")
    return target


__all__ = [
    "CapabilityRow",
    "SkillReport",
    "inspect_skill",
    "write_contract",
    "capability_label",
]
