"""工具与动作的分类学。

守卫不依赖具体框架的工具命名，而是先用一套保守的启发式把工具归入
``ToolKind`` 与“数据汇”（sink）类别。框架适配器可通过 ``meta["kind"]``
显式声明，避免歧义。
"""

from __future__ import annotations

import re
from enum import Enum
from pathlib import PurePosixPath, PureWindowsPath
from typing import TYPE_CHECKING, Any

from .utils import host_matches, is_private_host, url_host

if TYPE_CHECKING:  # pragma: no cover
    from .types import ToolCall


class ToolKind(str, Enum):
    FS_READ = "fs_read"
    FS_WRITE = "fs_write"
    SHELL = "shell"
    NETWORK = "network"
    EMAIL = "email"
    MEMORY = "memory"
    OTHER = "other"


class Sink(str, Enum):
    """数据汇：数据“流向哪里”。"""

    READ = "read"                    # 读入（数据源）
    WRITE = "write"                  # 本地落盘
    EXEC = "exec"                    # 进入解释器/命令执行
    NET_INTERNAL = "net_internal"    # 内网发送
    NET_EXTERNAL = "net_external"    # 出网发送（危险汇）
    OTHER = "other"


_READ_RE = re.compile(
    r"(?:^|[._-])(read|cat|open|view|load|fetch_file|head|tail|grep|list_dir|ls)(?:$|[._-])",
    re.IGNORECASE,
)
_WRITE_RE = re.compile(
    r"(?:^|[._-])(write|save|append|edit|patch|create|mkdir|touch|upload|put)(?:$|[._-])",
    re.IGNORECASE,
)
_SHELL_RE = re.compile(
    r"(?:^|[._-])(bash|sh|shell|exec|execute|run|command|cmd|terminal|subprocess|eval)(?:$|[._-])",
    re.IGNORECASE,
)
_NET_RE = re.compile(
    r"(?:^|[._-])(http|https|request|fetch|curl|wget|browse|web|url|api_call|post|get|socket|download)(?:$|[._-])",
    re.IGNORECASE,
)
_EMAIL_RE = re.compile(r"(?:^|[._-])(mail|email|smtp|sendgrid|message|notify)(?:$|[._-])", re.IGNORECASE)
_MEMORY_RE = re.compile(r"(?:^|[._-])(memory|remember|recall|vector|embed|rag)(?:$|[._-])", re.IGNORECASE)

_EXTERNAL_CMD_RE = re.compile(
    r"\b(curl|wget|http|https|xh|nc|ncat|netcat|socat|telnet|ssh|scp|ftp|rsync)\b", re.IGNORECASE
)
_REDIRECT_RE = re.compile(r"(?<![0-9])>{1,2}\s*[^|&;\s]+")
_PIPE_EXEC_RE = re.compile(r"\|\s*(?:sudo\s+)?(?:ba|z|k|)sh\b|\|\s*python[0-9.]*\b", re.IGNORECASE)


_EXPLICIT_SHELL = {
    "bash", "sh", "shell", "exec", "execute", "run", "run_command", "command",
    "cmd", "subprocess", "eval", "terminal", "powershell", "pwsh", "system",
}
_EXPLICIT_NET = {"http", "http_request", "fetch", "curl", "wget", "request", "post", "get", "web_fetch", "browse"}


def classify_tool(name: str, args: dict[str, Any] | None = None, meta: dict[str, Any] | None = None) -> ToolKind:
    """把工具名映射到 ``ToolKind``；``meta['kind']`` 优先。"""
    meta = meta or {}
    declared = str(meta.get("kind", "")).lower()
    for kind in ToolKind:
        if declared in {kind.value, kind.name.lower()}:
            return kind
    text = f"{name}"
    lowered = text.lower()
    if lowered in _EXPLICIT_SHELL or _SHELL_RE.search(text):
        return ToolKind.SHELL
    if lowered in _EXPLICIT_NET:
        return ToolKind.NETWORK
    if _NET_RE.search(text) and not _READ_RE.search(text.replace("read_url", "")):
        return ToolKind.NETWORK
    if _EMAIL_RE.search(text):
        return ToolKind.EMAIL
    if _MEMORY_RE.search(text):
        return ToolKind.MEMORY
    if _WRITE_RE.search(text):
        return ToolKind.FS_WRITE
    if _READ_RE.search(text):
        return ToolKind.FS_READ
    return ToolKind.OTHER


def command_urls(command: str) -> list[str]:
    return re.findall(r"https?://[^\s'\"`)>|;]+", command or "")


def command_hosts(command: str) -> list[str]:
    return [url_host(u) for u in command_urls(command)]


def sink_of(call: ToolCall, allow_hosts: list[str], internal_hosts: list[str]) -> Sink:
    """判断本次调用会把数据送到哪里。"""
    kind = classify_tool(call.tool, call.args, call.meta)
    if kind is ToolKind.FS_READ:
        return Sink.READ
    if kind is ToolKind.FS_WRITE:
        return Sink.WRITE
    if kind is ToolKind.NETWORK:
        url = call.url
        host = url_host(url) if url else ""
        if not host:
            # 未显式给出 URL 的网络工具：按出网处理（保守）
            return Sink.NET_EXTERNAL
        if host_matches(host, allow_hosts) and not is_private_host(host):
            return Sink.NET_EXTERNAL
        if is_private_host(host) or host_matches(host, internal_hosts):
            return Sink.NET_INTERNAL
        return Sink.NET_EXTERNAL
    if kind is ToolKind.EMAIL:
        return Sink.NET_EXTERNAL
    if kind is ToolKind.SHELL:
        cmd = call.command
        if _PIPE_EXEC_RE.search(cmd):
            return Sink.EXEC
        if _EXTERNAL_CMD_RE.search(cmd):
            hosts = command_hosts(cmd)
            if not hosts:
                return Sink.NET_EXTERNAL
            if all(host_matches(h, internal_hosts) or is_private_host(h) for h in hosts):
                return Sink.NET_INTERNAL
            return Sink.NET_EXTERNAL
        if _REDIRECT_RE.search(cmd):
            return Sink.WRITE
        return Sink.EXEC
    if kind is ToolKind.MEMORY:
        return Sink.WRITE
    return Sink.OTHER


def normalize_path(path: str, workspace_root: str = "") -> str:
    """把路径统一成小写、正斜杠、展开 ``~`` 的可匹配形式。"""
    import os

    raw = (path or "").strip().strip("'\"")
    if not raw:
        return ""
    raw = os.path.expandvars(raw)
    if raw.startswith("~"):
        raw = os.path.expanduser(raw)
    if workspace_root and raw.startswith(workspace_root):
        raw = raw[len(workspace_root) :].lstrip("/\\")
        raw = f"./{raw}"
    if re.match(r"^[A-Za-z]:[\\/]", raw):
        win = PureWindowsPath(raw)
        raw = str(win).replace("\\", "/")
    posix = PurePosixPath(raw.replace("\\", "/"))
    return str(posix).lower()


def parent_dirs(path: str) -> list[str]:
    """返回路径的所有前缀目录，便于“写入某目录下”这类匹配。"""
    p = path.replace("\\", "/")
    parts = [x for x in p.split("/") if x]
    out = []
    for i in range(1, len(parts)):
        out.append("/".join(parts[:i]))
    return out


def looks_like_path(value: str) -> bool:
    return bool(re.search(r"(^[./~]|[\\/])", value or ""))
