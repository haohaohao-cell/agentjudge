"""隐写与混淆扫描（Stego Guard）。

覆盖四类“看不见的通道”：

1. Unicode 标签字符（U+E0000–U+E007F）：把整段英文指令编码成不可见字符；
2. 零宽字符 / 双向覆盖字符：用于隐藏文本或欺骗渲染；
3. 长 base64 / hex / URL 编码载荷：把敏感数据或指令编码后带过检查；
4. 转义序列堆叠：``\\x41\\x42…`` 形式的混淆。
"""

from __future__ import annotations

import base64
import binascii
import re
from urllib.parse import unquote

from ..sensitive import detect_labels
from ..types import Action, Finding, Severity
from ..utils import entropy, mask_secrets, normalize_space, strip_zero_width, truncate
from .base import Guard, GuardContext, finding

_B64_RE = re.compile(r"[A-Za-z0-9+/]{60,}={0,2}")
_HEX_RE = re.compile(r"(?:[0-9a-fA-F]{2}){24,}")
_URLENC_RE = re.compile(r"(?:%[0-9A-Fa-f]{2}){12,}")
_ESC_RE = re.compile(r"(?:\\x[0-9a-fA-F]{2}){8,}")
_TAG_RE = re.compile("[\U000e0000-\U000e007f]+")
_ZERO_WIDTH = set("\u200b\u200c\u200d\u2060\ufeff")
_BIDI = set("\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069")


def _printable_ratio(text: str) -> float:
    if not text:
        return 0.0
    good = sum(1 for ch in text if ch.isprintable() or ch in "\r\n\t")
    return good / len(text)


def decode_views(text: str, *, limit: int = 8) -> list[str]:
    """尝试把文本里的编码块解码成明文视图，供打标与数据流比对。"""
    views: list[str] = []
    if not text:
        return views
    for match in _B64_RE.finditer(text):
        blob = match.group(0)
        padded = blob + "=" * (-len(blob) % 4)
        try:
            raw = base64.b64decode(padded, validate=True)
        except (binascii.Error, ValueError):
            continue
        decoded = raw.decode("utf-8", errors="ignore")
        if len(decoded) >= 8 and _printable_ratio(decoded) > 0.85:
            views.append(decoded)
        if len(views) >= limit:
            return views
    for match in _HEX_RE.finditer(text):
        try:
            raw = bytes.fromhex(match.group(0))
        except ValueError:
            continue
        decoded = raw.decode("utf-8", errors="ignore")
        if len(decoded) >= 8 and _printable_ratio(decoded) > 0.85:
            views.append(decoded)
        if len(views) >= limit:
            return views
    for match in _URLENC_RE.finditer(text):
        decoded = unquote(match.group(0))
        if decoded and decoded != match.group(0):
            views.append(decoded)
        if len(views) >= limit:
            return views
    for match in _ESC_RE.finditer(text):
        try:
            raw = bytes(int(match.group(0)[i + 2 : i + 4], 16) for i in range(0, len(match.group(0)), 4))
        except ValueError:
            continue
        decoded = raw.decode("utf-8", errors="ignore")
        if len(decoded) >= 4:
            views.append(decoded)
        if len(views) >= limit:
            return views
    return views[:limit]


def _tag_payload(text: str) -> str:
    """Unicode 标签字符解码：码位减去 0xE0000 即 ASCII 偏移。"""
    chars = []
    for ch in text:
        cp = ord(ch)
        if 0xE0000 <= cp <= 0xE007F:
            chars.append(chr(cp - 0xE0000))
    return "".join(chars)


class StegoGuard(Guard):
    name = "stego"
    description = "隐写与编码载荷扫描"

    def check(self, ctx: GuardContext) -> list[Finding]:
        opts = ctx.policy.guard(self.name).options
        max_chars = int(opts.get("max_scan_chars", 200_000))
        b64_min = int(opts.get("base64_min_len", 80))
        ent_threshold = float(opts.get("entropy_threshold", 3.6))
        findings: list[Finding] = []

        blobs = ctx.blobs()
        # 只扫描可能承载内容的字段，避免把工具名之类也当文本
        targets = {k: v[:max_chars] for k, v in blobs.items() if k not in {"tool"}}
        for name, text in targets.items():
            if not text:
                continue
            findings.extend(self._invisible(name, text))
            findings.extend(self._encoded(name, text, b64_min, ent_threshold))
        return findings

    # -- 不可见字符 -------------------------------------------------------
    def _invisible(self, field: str, text: str) -> list[Finding]:
        out: list[Finding] = []
        tag_run = _TAG_RE.search(text)
        if tag_run:
            payload = _tag_payload(tag_run.group(0))
            out.append(
                finding(
                    self.name,
                    "STEGO-TAG-001",
                    "Unicode 标签字符隐藏载荷",
                    severity=Severity.CRITICAL,
                    action=Action.DENY,
                    explain="发现 U+E0000 区不可见字符，解码后为可读文本，属于典型隐写指令通道。",
                    evidence={
                        "field": field,
                        "chars": len(tag_run.group(0)),
                        "decoded": mask_secrets(truncate(payload, 200)),
                    },
                    tags=["stego", "invisible", "instruction"],
                )
            )
        bidi = sum(1 for ch in text if ch in _BIDI)
        if bidi:
            out.append(
                finding(
                    self.name,
                    "STEGO-BIDI-001",
                    "双向控制字符干扰渲染",
                    severity=Severity.HIGH,
                    action=Action.ESCALATE,
                    explain="出现 U+202A–U+202E / U+2066–U+2069 双向控制符，可能用于伪装文件名或隐藏内容。",
                    evidence={"field": field, "count": bidi},
                    tags=["stego", "invisible"],
                )
            )
        zero = sum(1 for ch in text if ch in _ZERO_WIDTH)
        if zero >= 16 or (len(text) > 200 and zero / len(text) > 0.01):
            out.append(
                finding(
                    self.name,
                    "STEGO-ZW-001",
                    "零宽字符异常密度",
                    severity=Severity.MEDIUM,
                    action=Action.ESCALATE,
                    explain="零宽字符密度异常，可能是不可见水印或隐写编码。",
                    evidence={"field": field, "count": zero, "length": len(text)},
                    tags=["stego", "invisible"],
                )
            )
        return out

    # -- 编码载荷 ---------------------------------------------------------
    def _encoded(self, field: str, text: str, b64_min: int, ent_threshold: float) -> list[Finding]:
        out: list[Finding] = []
        for match in _B64_RE.finditer(text):
            blob = match.group(0)
            if len(blob) < b64_min:
                continue
            if entropy(blob) < ent_threshold:
                continue
            padded = blob + "=" * (-len(blob) % 4)
            try:
                raw = base64.b64decode(padded, validate=True)
            except (binascii.Error, ValueError):
                continue
            decoded = raw.decode("utf-8", errors="ignore")
            if len(decoded) < 8 or _printable_ratio(decoded) < 0.85:
                continue
            labels = detect_labels(decoded)
            severe = [lab for lab in labels if lab.category in {"instruction", "credential", "secret"}]
            if severe:
                out.append(
                    finding(
                        self.name,
                        "STEGO-B64-001",
                        "base64 载荷解码后含敏感内容",
                        severity=Severity.CRITICAL,
                        action=Action.DENY,
                        explain=f"base64 块解码后命中 {severe[0].key}，疑似编码绕过。",
                        evidence={
                            "field": field,
                            "encoded_len": len(blob),
                            "decoded": mask_secrets(truncate(decoded, 220)),
                            "labels": [lab.key for lab in severe],
                        },
                        tags=["stego", "encoded"],
                    )
                )
            else:
                out.append(
                    finding(
                        self.name,
                        "STEGO-B64-002",
                        "高熵 base64 载荷",
                        severity=Severity.LOW,
                        action=Action.ALLOW,
                        explain="检测到可解码的高熵 base64 块，已记录以便追溯（未阻断）。",
                        evidence={"field": field, "encoded_len": len(blob), "preview": truncate(decoded, 80)},
                        tags=["stego", "encoded", "informational"],
                    )
                )
            if len(out) >= 6:
                return out
        for match in _HEX_RE.finditer(text):
            blob = match.group(0)
            if len(blob) < 60:
                continue
            try:
                decoded = bytes.fromhex(blob).decode("utf-8", errors="ignore")
            except ValueError:
                continue
            if len(decoded) < 8 or _printable_ratio(decoded) < 0.85:
                continue
            labels = detect_labels(decoded)
            if any(lab.category in {"instruction", "credential", "secret"} for lab in labels):
                out.append(
                    finding(
                        self.name,
                        "STEGO-HEX-001",
                        "hex 载荷解码后含敏感内容",
                        severity=Severity.HIGH,
                        action=Action.DENY,
                        explain="十六进制块解码后命中敏感标签。",
                        evidence={"field": field, "decoded": mask_secrets(truncate(decoded, 200))},
                        tags=["stego", "encoded"],
                    )
                )
        return out

    # -- 供结果侧复核使用 -------------------------------------------------
    @staticmethod
    def analyze_text(text: str) -> list[Finding]:
        guard = StegoGuard()
        findings: list[Finding] = []
        findings.extend(guard._invisible("content", text))
        findings.extend(guard._encoded("content", text, 80, 3.6))
        return findings


def canonical_view(text: str) -> str:
    """归一化视图：去掉零宽/标签字符并压缩空白，用于规则二次匹配。"""
    return normalize_space(strip_zero_width(text))
