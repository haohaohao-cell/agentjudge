"""examples/mcp_client.py 的端到端回归：示例必须真的能跑通，而不是文档里的摆设。"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import unittest

from helpers import ROOT

EXAMPLE = ROOT / "examples" / "mcp_client.py"


class MCPClientExampleTest(unittest.TestCase):
    def test_example_runs_green(self):
        env = os.environ.copy()
        env["PYTHONIOENCODING"] = "utf-8"
        env["NO_COLOR"] = "1"
        result = subprocess.run(
            [sys.executable, str(EXAMPLE), "--json"],
            cwd=str(ROOT),
            env=env,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=120,
        )
        self.assertEqual(result.returncode, 0, f"stdout={result.stdout}\nstderr={result.stderr}")
        payload = json.loads(result.stdout)
        self.assertTrue(payload["ok"], payload)
        steps = {step["step"]: step for step in payload["steps"]}
        self.assertEqual(len(steps), 9)
        self.assertTrue(steps["initialize"]["ok"])
        self.assertTrue(steps["allow-read"]["ok"])
        self.assertTrue(steps["observe-clean"]["ok"])
        self.assertTrue(steps["deny-command"]["ok"])
        self.assertTrue(steps["quarantine-injection"]["ok"])
        self.assertTrue(steps["deny-polluted-session"]["ok"])
        self.assertTrue(steps["verify-audit"]["ok"])
        self.assertGreaterEqual(steps["verify-audit"]["detail"]["records"], 7)


if __name__ == "__main__":
    unittest.main()
