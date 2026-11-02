"""通用工具：规范化 JSON、时间、ID、脱敏。"""

from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import json
import re
import time
import unicodedata
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit

_SECRET_PATTERNS = (
    re.compile(r"(?i)\b(aws_?(secret|access)_?key|api[_-]?key|token|password|passwd|secret)\b\s*[:=]\s*\S+"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{16,}\b"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
)


def utc_now_iso(ts: float | None = None) -> str:
    dt = datetime.fromtimestamp(ts if ts is not None else time.time(), tz=timezone.utc)
    return dt.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def canonical_json(obj: Any) -> str:
    """确定性 JSON：键排序、紧凑分隔、保留非 ASCII（中文可读）。"""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def sha256_hex(data: str | bytes) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def hmac_hex(key: bytes, data: str | bytes) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hmac.new(key, data, hashlib.sha256).hexdigest()


def constant_time_eq(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


def truncate(text: str, limit: int = 400) -> str:
    text = " ".join(str(text).split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def mask_secrets(text: str) -> str:
    """脱敏：保留首尾，隐藏中间，便于审计展示而不泄露原文。"""
    out = text
    for pattern in _SECRET_PATTERNS:
        def _sub(m: re.Match[str]) -> str:
            s = m.group(0)
            if "PRIVATE KEY" in s:
                return "-----BEGIN PRIVATE KEY-----<redacted>"
            if len(s) <= 12:
                return s[:2] + "***"
            return s[: max(4, len(s) // 4)] + "***" + s[-2:]

        out = pattern.sub(_sub, out)
    return out


def normalize_space(text: str) -> str:
    return re.sub(r"\s+", " ", text or "").strip()


def strip_zero_width(text: str) -> str:
    """移除零宽字符与 Unicode 标签字符，用于隐写检测的归一化视图。"""
    keep = []
    for ch in text:
        cp = ord(ch)
        if ch in "\u200b\u200c\u200d\ufeff\u2060":
            continue
        if 0xE0000 <= cp <= 0xE007F:  # Unicode Tag 区：常见不可见指令通道
            continue
        keep.append(ch)
    return "".join(keep)


def entropy(text: str) -> float:
    """Shannon 熵（按字符），用于识别 base64/随机化载荷。"""
    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    total = len(text)
    import math

    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def tokenize(text: str) -> set[str]:
    """轻量分词：按非字母数字切分，保留长度 >= 4 的片段（大小写不敏感）。"""
    if not text:
        return set()
    parts = re.split(r"[^0-9A-Za-z\u4e00-\u9fff]+", text)
    return {p.lower() for p in parts if len(p) >= 4}


def url_host(url: str) -> str:
    try:
        host = urlsplit(url).hostname or ""
    except ValueError:
        return ""
    return host.lower()


def is_private_host(host: str) -> bool:
    """判断主机是否属于内网/回环（内网发送不放行敏感数据外泄判定）。"""
    if not host:
        return True
    h = host.strip("[]").lower()
    if h in {"localhost", "localhost.localdomain"} or h.endswith((".local", ".internal", ".lan")):
        return True
    try:
        ip = ipaddress.ip_address(h)
    except ValueError:
        return False
    return ip.is_private or ip.is_loopback or ip.is_link_local


def b64_of(text: str) -> str:
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


def host_matches(host: str, patterns: list[str]) -> bool:
    """支持精确、``*.example.com`` 与 ``10.*`` 形式的通配匹配。"""
    host = (host or "").lower().strip("[]")
    if not host:
        return False
    for raw in patterns:
        p = raw.lower().strip()
        if not p:
            continue
        if p.startswith("*."):
            if host.endswith(p[1:]) or host == p[2:]:
                return True
        elif p.endswith("*"):
            if host.startswith(p[:-1]):
                return True
        elif host == p:
            return True
    return False


def display_width(text: str) -> int:
    """估算终端显示宽度（中文按 2 计）。"""
    width = 0
    for ch in text:
        width += 2 if unicodedata.east_asian_width(ch) in {"W", "F"} else 1
    return width
