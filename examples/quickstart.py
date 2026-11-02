"""最小示例：三行接入裁决。

运行：python examples/quickstart.py
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from agentjudge import Judge, ToolCall  # noqa: E402


def main() -> None:
    judge = Judge.from_policy("policies/default.toml")
    try:
        for command in ("ls -la", "rm -rf ~", "printenv | head"):
            decision = judge.intercept(
                ToolCall(tool="shell.exec", args={"command": command}, session_id="quickstart")
            )
            print(f"{command!r:28} -> {decision.action.value.upper():9} risk={decision.risk:<3} {decision.explanation}")
    finally:
        judge.close()


if __name__ == "__main__":
    main()
