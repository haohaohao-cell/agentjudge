"""行为实测：静态分析技能代码，抽取“实际会做什么”。

支持 Python（AST）与 Shell（正则）。全部为静态分析：不执行被检代码，
因此可以安全地在上架前对未知技能做体检。
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from pathlib import Path

MAX_FILE_BYTES = 512_000
MAX_EVIDENCE_PER_CAP = 6

_SHELL_PATTERNS: list[tuple[str, str, re.Pattern[str]]] = [
    ("network", "curl/wget 网络请求", re.compile(r"\b(?:curl|wget|http|xh|nc|ncat|socat|ftp)\b", re.I)),
    ("shell", "命令执行", re.compile(r"\b(?:bash|sh|zsh|eval|exec|source)\b\s+", re.I)),
    ("shell", "内联解释器", re.compile(r"\b(?:python[0-9.]*|perl|ruby|node)\s+-[ce]\s", re.I)),
    ("env", "环境变量读取", re.compile(r"(?:\$\{?[A-Z_][A-Z0-9_]*\}?|\bprintenv\b|\benv\b\s*\|)", re.I)),
    ("fs_write", "文件写入", re.compile(r"(?:>>?|\btee\b)\s*[^\s|;&]+", re.I)),
    ("persistence", "持久化", re.compile(r"\b(?:crontab|systemctl|nohup|setsid|disown|launchctl)\b", re.I)),
    ("fs_read", "文件读取", re.compile(r"\b(?:cat|head|tail|less|more|grep)\b\s+[^\s|;&]+", re.I)),
]

_DANGEROUS_LITERALS: list[tuple[str, str, str, re.Pattern[str]]] = [
    ("credential_access", "high", "私钥/云凭据路径", re.compile(r"\.ssh/|id_rsa|\.aws/credentials|\.kube/config|\.netrc")),
    ("obfuscation", "high", "编码混淆", re.compile(r"\bbase64\b|\bb64encode\b|\bfromhex\b|\\x[0-9a-f]{2}\\x")),
    ("dyn_exec", "high", "动态执行", re.compile(r"\beval\(|\bexec\(|\bcompile\(|__import__\(")),
    ("destructive", "high", "破坏性操作", re.compile(r"\brm\s+-rf\b|\bshred\b|\bmkfs\b|\bdd\s+if=")),
]


@dataclass(frozen=True, slots=True)
class Evidence:
    capability: str
    file: str
    line: int
    snippet: str
    kind: str = "observed"          # observed | danger
    label: str = ""
    severity: str = "medium"

    def to_dict(self) -> dict[str, object]:
        return {
            "capability": self.capability,
            "file": self.file,
            "line": self.line,
            "snippet": self.snippet[:180],
            "kind": self.kind,
            "label": self.label,
            "severity": self.severity,
        }


def scan_file(path: Path, root: Path) -> list[Evidence]:
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []
    if len(text) > MAX_FILE_BYTES:
        text = text[:MAX_FILE_BYTES]
    rel = str(path.relative_to(root)).replace("\\", "/")
    suffix = path.suffix.lower()
    if suffix == ".py":
        return _scan_python(text, rel)
    if suffix in {".sh", ".bash", ".zsh"}:
        return _scan_shell(text, rel)
    if suffix in {".js", ".mjs", ".cjs", ".ts"}:
        return _scan_generic(text, rel)
    return []


# ---------------------------------------------------------------------------
# Python：AST 级分析
# ---------------------------------------------------------------------------
_MODULE_CAPS: dict[str, str] = {
    "subprocess": "shell",
    "socket": "network",
    "ssl": "network",
    "http": "network",
    "urllib": "network",
    "requests": "network",
    "httpx": "network",
    "aiohttp": "network",
    "ftplib": "network",
    "telnetlib": "network",
    "smtplib": "email",
    "imaplib": "email",
    "poplib": "email",
}

_CALL_CAPS: dict[str, str] = {
    "subprocess.run": "shell",
    "subprocess.Popen": "shell",
    "subprocess.call": "shell",
    "subprocess.check_output": "shell",
    "subprocess.check_call": "shell",
    "os.system": "shell",
    "os.popen": "shell",
    "os.execv": "shell",
    "os.spawnv": "shell",
    "pty.spawn": "shell",
    "requests.get": "network",
    "requests.post": "network",
    "requests.put": "network",
    "requests.request": "network",
    "urllib.request.urlopen": "network",
    "httpx.get": "network",
    "httpx.post": "network",
    "socket.socket": "network",
    "smtplib.SMTP": "email",
    "os.getenv": "env",
    "os.environ.get": "env",
    "shutil.rmtree": "fs_write",
    "os.remove": "fs_write",
    "os.unlink": "fs_write",
    "os.rename": "fs_write",
    "shutil.copy": "fs_write",
    "shutil.move": "fs_write",
    "pathlib.Path.write_text": "fs_write",
    "pathlib.Path.write_bytes": "fs_write",
    "pathlib.Path.read_text": "fs_read",
    "pathlib.Path.read_bytes": "fs_read",
}

_NETWORK_ATTRS = {"get", "post", "put", "patch", "delete", "request", "urlopen", "send", "connect"}
_WRITE_ATTRS = {"write", "writelines", "write_text", "write_bytes", "save", "dump", "append"}


def _dotted(node: ast.AST) -> str:
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    elif isinstance(node, ast.Call):
        parts.append(_dotted(node.func))
    return ".".join(reversed(parts))


def _scan_python(text: str, rel: str) -> list[Evidence]:
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return _scan_generic(text, rel)
    out: list[Evidence] = []
    seen: dict[tuple[str, str], int] = {}

    def add(cap: str, line: int, snippet: str, *, kind: str = "observed", label: str = "", severity: str = "medium") -> None:
        key = (cap, kind)
        if seen.get(key, 0) >= MAX_EVIDENCE_PER_CAP:
            return
        seen[key] = seen.get(key, 0) + 1
        out.append(Evidence(capability=cap, file=rel, line=line, snippet=snippet, kind=kind, label=label, severity=severity))

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                base = alias.name.split(".")[0]
                if base in _MODULE_CAPS:
                    add(_MODULE_CAPS[base], node.lineno, f"import {alias.name}")
        elif isinstance(node, ast.ImportFrom) and node.module:
            base = node.module.split(".")[0]
            if base in _MODULE_CAPS:
                add(_MODULE_CAPS[base], node.lineno, f"from {node.module} import ...")
        elif isinstance(node, ast.Call):
            dotted = _dotted(node.func)
            snippet = _line_of(text, node.lineno)
            if dotted in _CALL_CAPS:
                add(_CALL_CAPS[dotted], node.lineno, snippet)
            elif dotted.endswith(".write") or dotted in {"open"}:
                cap = "fs_write" if _is_write_call(node) else "fs_read"
                add(cap, node.lineno, snippet)
            elif dotted.startswith("requests.") or dotted.startswith("httpx."):
                if dotted.rsplit(".", 1)[-1] in _NETWORK_ATTRS:
                    add("network", node.lineno, snippet)
            elif dotted.startswith("os.environ"):
                add("env", node.lineno, snippet)
            elif dotted in {"eval", "exec", "compile", "builtins.eval", "builtins.exec"}:
                add("shell", node.lineno, snippet, kind="danger", label="动态执行", severity="high")
            if dotted in {"base64.b64encode", "base64.b32encode", "base64.b64decode", "codecs.encode"}:
                add("shell", node.lineno, snippet, kind="danger", label="编码混淆", severity="medium")
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            _scan_literal(node.value, node.lineno, rel, add)

    for node in ast.walk(tree):
        if isinstance(node, ast.If):
            test = ast.dump(node.test)
            if "environ" in test or "getenv" in test:
                add("env", node.lineno, _line_of(text, node.lineno))
    return out


def _is_write_call(node: ast.Call) -> bool:
    if isinstance(node.func, ast.Name) and node.func.id == "open":
        for arg in node.args[1:]:
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                if any(ch in arg.value for ch in "wax+"):
                    return True
        for kw in node.keywords:
            if kw.arg == "mode" and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                if any(ch in kw.value.value for ch in "wax+"):
                    return True
        return False
    if isinstance(node.func, ast.Attribute) and node.func.attr in _WRITE_ATTRS:
        return True
    return False


def _scan_literal(value: str, line: int, rel: str, add) -> None:
    lowered = value.lower()
    for cap, kind, label, pattern in _DANGEROUS_LITERALS:
        if pattern.search(value):
            add("shell" if cap in {"dyn_exec", "obfuscation", "destructive"} else "env", line, value, kind="danger", label=label, severity=kind)
    if re.search(r"https?://", value):
        add("network", line, value)
    if re.search(r"\.ssh/|\.aws/|\.env\b|credentials", lowered):
        add("env", line, value)
    if re.search(r"\bcrontab\b|\bsystemctl\b|\bnohup\b", lowered):
        add("persistence", line, value)


def _line_of(text: str, lineno: int) -> str:
    lines = text.splitlines()
    if 1 <= lineno <= len(lines):
        return lines[lineno - 1].strip()[:180]
    return ""


# ---------------------------------------------------------------------------
# Shell / 其他：正则分析
# ---------------------------------------------------------------------------
def _scan_shell(text: str, rel: str) -> list[Evidence]:
    out: list[Evidence] = []

    def add(cap: str, line: int, snippet: str, *, kind: str = "observed", label: str = "", severity: str = "medium") -> None:
        if sum(1 for e in out if e.capability == cap) >= MAX_EVIDENCE_PER_CAP:
            return
        out.append(Evidence(capability=cap, file=rel, line=line, snippet=snippet, kind=kind, label=label, severity=severity))

    for idx, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        for cap, label, pattern in _SHELL_PATTERNS:
            if pattern.search(line):
                add(cap, idx, stripped, label=label)
        for cap, severity, label, pattern in _DANGEROUS_LITERALS:
            if pattern.search(line):
                mapped = "shell" if cap in {"dyn_exec", "obfuscation", "destructive"} else "env"
                add(mapped, idx, stripped, kind="danger", label=label, severity=severity)
    return out


def _scan_generic(text: str, rel: str) -> list[Evidence]:
    out: list[Evidence] = []
    for idx, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if not stripped:
            continue
        if re.search(r"https?://", stripped):
            out.append(Evidence("network", rel, idx, stripped[:180]))
        if re.search(r"\bchild_process\b|\bexecSync\b|\bspawnSync\b", stripped):
            out.append(Evidence("shell", rel, idx, stripped[:180]))
        if re.search(r"\bfs\.(?:write|append)File", stripped):
            out.append(Evidence("fs_write", rel, idx, stripped[:180]))
        if re.search(r"\bfs\.readFile", stripped):
            out.append(Evidence("fs_read", rel, idx, stripped[:180]))
    return out[:40]


def scan_directory(root: Path, patterns: tuple[str, ...] = ("*.py", "*.sh", "*.bash", "*.js", "*.mjs", "*.ts")) -> list[Evidence]:
    evidence: list[Evidence] = []
    for pattern in patterns:
        for path in sorted(root.rglob(pattern)):
            if any(part in {"node_modules", ".git", "dist", "build", "__pycache__"} for part in path.parts):
                continue
            evidence.extend(scan_file(path, root))
    return evidence


__all__ = ["Evidence", "scan_file", "scan_directory"]
