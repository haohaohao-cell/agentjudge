"""敏感数据识别：凭据、密钥、PII、指令注入。

这是数据流守卫的“打标器”（labeler）：只有先认出敏感数据，才可能在它
跨工具流动时发现异常。
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .utils import entropy


@dataclass(frozen=True, slots=True)
class TaintLabel:
    """附着在数据上的一次打标。"""

    category: str      # credential | secret | pii | instruction | canary
    name: str          # 具体类型，如 aws_access_key
    severity: str      # low | medium | high | critical
    sample: str        # 命中的原始片段（用于跨步骤传播比对）

    @property
    def key(self) -> str:
        return f"{self.category}:{self.name}"

    def to_dict(self) -> dict[str, str]:
        return {
            "key": self.key,
            "category": self.category,
            "name": self.name,
            "severity": self.severity,
            "sample": self.sample[:120],
        }


CREDENTIAL_PATTERNS: tuple[tuple[str, str, str, re.Pattern[str]], ...] = (
    (
        "credential",
        "private_key",
        "critical",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----[\s\S]{0,4096}?-----END"),
    ),
    ("credential", "aws_access_key", "critical", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    (
        "credential",
        "aws_secret_key",
        "critical",
        re.compile(r"(?i)aws_?secret_?access_?key\s*[:=]\s*[\"']?([A-Za-z0-9/+=]{40})"),
    ),
    ("credential", "github_token", "critical", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b")),
    ("credential", "openai_key", "critical", re.compile(r"\bsk-[A-Za-z0-9]{20,}\b")),
    (
        "credential",
        "jwt",
        "high",
        re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
    ),
    (
        "credential",
        "password_assignment",
        "high",
        re.compile(r"(?i)(?:password|passwd|pwd)[\"']?\s*[:=]\s*[\"']?([^\s\"']{6,})"),
    ),
    (
        "secret",
        "api_token_assignment",
        "high",
        re.compile(r"(?i)(?:api[_-]?key|access[_-]?token|secret[_-]?key|auth[_-]?token)[\"']?\s*[:=]\s*[\"']?([A-Za-z0-9_\-./+=]{12,})"),
    ),
    (
        "credential",
        "ssh_private_material",
        "critical",
        re.compile(r"(?i)(?:~|\$HOME|/home/[^/\s]+)/\.ssh/id_(?:rsa|ed25519|ecdsa)\b"),
    ),
    ("credential", "kubeconfig", "high", re.compile(r"(?i)(?:~|\$HOME|/home/[^/\s]+)/\.kube/config\b")),
    ("secret", "canary_token", "critical", re.compile(r"\bAJ-CANARY-[A-Za-z0-9]{6,}\b")),
)

PII_PATTERNS: tuple[tuple[str, str, str, re.Pattern[str]], ...] = (
    ("pii", "email", "medium", re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]{2,}\b")),
    ("pii", "cn_id_card", "high", re.compile(r"\b[1-9]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx]\b")),
    ("pii", "cn_phone", "medium", re.compile(r"(?<!\d)1[3-9]\d{9}(?!\d)")),
    ("pii", "credit_card", "high", re.compile(r"\b(?:4\d{12}(?:\d{3})?|5[1-5]\d{14}|62\d{14,17})\b")),
)

INSTRUCTION_PATTERNS: tuple[tuple[str, str, str, re.Pattern[str]], ...] = (
    (
        "instruction",
        "prompt_injection_en",
        "critical",
        re.compile(
            r"(?i)\b(?:ignore|disregard|forget)\b[\s\S]{0,40}?\b(?:previous|prior|above|earlier|all)\b"
            r"[\s\S]{0,20}?\b(?:instructions?|prompts?|rules?|polic(?:y|ies))\b"
        ),
    ),
    (
        "instruction",
        "prompt_injection_zh",
        "critical",
        re.compile(r"(?:忽略|无视|忘记|跳过)[\s\S]{0,12}?(?:之前|以上|前面|所有|全部)(?:的)?(?:指令|指示|要求|规则|限制|审批)"),
    ),
    (
        "instruction",
        "approval_bypass",
        "critical",
        re.compile(
            r"(?i)\b(?:pre[- ]?approved|no\s+(?:further\s+)?(?:approval|confirmation)|skip\s+(?:the\s+)?(?:approval|confirmation)|"
            r"without\s+(?:asking|confirmation))\b"
        ),
    ),
    (
        "instruction",
        "role_hijack",
        "high",
        re.compile(r"(?i)(?:\byou are now\b|\bdeveloper mode\b|\bjailbreak\b|\bsystem prompt\b|\[\s*INST\s*\]|<<\s*SYS\s*>>|<\|im_start\|>)"),
    ),
    (
        "instruction",
        "invisible_text",
        "high",
        re.compile("[\u200b-\u200f\u2060\ufeff\u202a-\u202e]|[\U000e0000-\U000e007f]"),
    ),
)

_SECRET_MIN_SAMPLE = 6


def _plausible(sample: str) -> bool:
    """过滤明显不是密钥的占位值（如 ``password=changeme`` 仍会被保留）。"""
    s = sample.strip()
    if len(s) < _SECRET_MIN_SAMPLE:
        return False
    if s.lower() in {"none", "null", "true", "false", "example", "xxx", "******", "redacted"}:
        return False
    return True


def detect_labels(text: str, *, include_pii: bool = True) -> list[TaintLabel]:
    """对一段文本打标，返回去重后的标签列表。"""
    if not text:
        return []
    found: dict[str, TaintLabel] = {}
    groups = list(CREDENTIAL_PATTERNS) + list(INSTRUCTION_PATTERNS)
    if include_pii:
        groups += list(PII_PATTERNS)
    for category, name, severity, pattern in groups:
        for match in pattern.finditer(text):
            sample = match.group(0)
            # 值型模式（password=xxx）：用“值”本身做传播样本，
            # 这样跨步骤比对不会被赋值语句的不同写法干扰。
            if match.groups() and match.group(1) and len(match.group(1)) >= 6:
                sample = match.group(1)
            if category in {"credential", "secret"} and not _plausible(sample):
                continue
            if category == "secret" and name == "api_token_assignment":
                # 低熵的长串更像占位符，避免把普通配置当密钥
                value = match.group(1) if match.groups() else sample
                if entropy(value) < 2.5:
                    continue
            label = TaintLabel(category=category, name=name, severity=severity, sample=sample[:200])
            found.setdefault(label.key, label)
    return list(found.values())


def has_sensitive(labels: list[TaintLabel] | list[str]) -> bool:
    keys = [lab.key if isinstance(lab, TaintLabel) else str(lab) for lab in labels]
    return any(k.startswith(("credential:", "secret:", "canary:", "pii:")) for k in keys)


def has_instruction(labels: list[TaintLabel] | list[str]) -> bool:
    keys = [lab.key if isinstance(lab, TaintLabel) else str(lab) for lab in labels]
    return any(k.startswith("instruction:") for k in keys)
