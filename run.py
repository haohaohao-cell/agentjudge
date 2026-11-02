#!/usr/bin/env python3
"""零安装启动器。

    python run.py demo
    python run.py serve
    python run.py intercept --tool shell.exec --arg "command=rm -rf ~"

效果等价于 ``PYTHONPATH=src python -m agentjudge <命令>``，避免 Windows/
PowerShell 下设置环境变量的麻烦。
"""

from __future__ import annotations

import os
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(ROOT, "src"))

from agentjudge.cli import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
