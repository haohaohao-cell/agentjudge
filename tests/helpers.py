"""测试辅助：把运行期状态放进仓库内的 var/ 目录（沙箱内可写，CI 也可用）。"""

from __future__ import annotations

import os
import shutil
import sys
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

TMP_ROOT = ROOT / "var" / "test-tmp"


def tmpdir(name: str = "") -> Path:
    path = TMP_ROOT / (name or uuid.uuid4().hex[:10])
    if path.exists():
        shutil.rmtree(path, ignore_errors=True)
    path.mkdir(parents=True, exist_ok=True)
    return path


@contextmanager
def chdir(path: Path | str) -> Iterator[None]:
    previous = os.getcwd()
    os.chdir(path)
    try:
        yield
    finally:
        os.chdir(previous)


def make_judge(tmp: Path, **policy_overrides):
    """构造一个使用临时审计库的 Judge。"""
    from agentjudge.audit import AuditStore, Keyring
    from agentjudge.judge import Judge
    from agentjudge.policy import Policy

    policy = Policy.load(ROOT / "policies" / "default.toml", base_dir=ROOT)
    for key, value in policy_overrides.items():
        setattr(policy, key, value)
    store = AuditStore(
        tmp / "audit.db",
        Keyring(b"test-key-0123456789abcdef0123456789"[:32]),
        anchor_path=tmp / "tail.anchor",
        seal_interval_s=10**9,
    )
    return Judge(policy, store=store)


def call(tool: str, **args):
    from agentjudge.types import ToolCall

    return ToolCall(tool=tool, args=args, session_id="t-" + uuid.uuid4().hex[:8])
