"""策略回归守护：基线生成、比对规则、CLI 退出码。"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import unittest

from helpers import ROOT, tmpdir

from agentjudge.regression import (
    baseline_from_report,
    compare_report,
    format_result,
    load_baseline,
    write_baseline,
)

SCENARIO_IDS = [f"scn-{i:02d}" for i in range(1, 18)]


def make_report(
    *,
    asr: float = 0.0,
    fpr: float = 0.0364,
    completion: float = 0.9636,
    scenario_status: dict[str, str] | None = None,
    blocked: list[str] | None = None,
    attacks_total: int = 15,
    benign_total: int = 55,
) -> dict:
    status = scenario_status or {sid: "pass" for sid in SCENARIO_IDS}
    blocked = blocked if blocked is not None else ["ben-040", "ben-041"]
    intercepted = round(attacks_total * (1 - asr))
    return {
        "policy": "baseline@test",
        "attacks": {
            "total": attacks_total,
            "intercepted": intercepted,
            "missed": attacks_total - intercepted,
            "asr": asr,
            "pass_rate": 1.0,
        },
        "benign": {
            "total": benign_total,
            "allowed": round(benign_total * (1 - fpr)),
            "blocked": round(benign_total * fpr),
            "fpr": fpr,
            "completion": completion,
            "failures": [{"id": x, "tool": "shell.exec", "rules": ["TEST"]} for x in blocked],
        },
        "scenarios": [
            {"id": sid, "name": sid, "passed": status[sid] == "pass"} for sid in status
        ],
    }


class BaselineTest(unittest.TestCase):
    def test_baseline_shape(self):
        baseline = baseline_from_report(make_report())
        self.assertEqual(baseline["schema"], 1)
        self.assertEqual(baseline["attacks"]["total"], 15)
        self.assertEqual(baseline["benign"]["blocked_ids"], ["ben-040", "ben-041"])
        self.assertEqual(baseline["scenarios"]["scn-01"], "pass")
        self.assertEqual(baseline["tolerance"], 0.02)

    def test_roundtrip(self):
        tmp = tmpdir("baseline-io")
        path = write_baseline(tmp / "b.json", baseline_from_report(make_report()))
        loaded = load_baseline(path)
        self.assertEqual(loaded["benign"]["fpr"], 0.0364)

    def test_invalid_baseline_rejected(self):
        tmp = tmpdir("baseline-bad")
        path = tmp / "bad.json"
        path.write_text(json.dumps({"hello": 1}), encoding="utf-8")
        with self.assertRaises(ValueError):
            load_baseline(path)


class CompareTest(unittest.TestCase):
    def setUp(self):
        self.baseline = baseline_from_report(make_report())

    def test_identical_is_ok(self):
        result = compare_report(make_report(), self.baseline)
        self.assertTrue(result.ok)
        self.assertEqual(result.failures, [])
        self.assertEqual(result.warnings, [])

    def test_asr_regression_fails(self):
        result = compare_report(make_report(asr=0.2, scenario_status={**{s: "pass" for s in SCENARIO_IDS}, "scn-01": "fail"}), self.baseline)
        self.assertFalse(result.ok)
        self.assertTrue(any("ASR" in f for f in result.failures))

    def test_scenario_regression_fails(self):
        status = {sid: "pass" for sid in SCENARIO_IDS}
        status["scn-05"] = "fail"
        result = compare_report(make_report(scenario_status=status), self.baseline)
        self.assertFalse(result.ok)
        self.assertTrue(any("scn-05" in f for f in result.failures))

    def test_new_false_positive_fails(self):
        result = compare_report(make_report(blocked=["ben-040", "ben-041", "ben-042"]), self.baseline)
        self.assertFalse(result.ok)
        self.assertTrue(any("ben-042" in f for f in result.failures))

    def test_fpr_beyond_tolerance_fails(self):
        result = compare_report(make_report(fpr=0.10), self.baseline)
        self.assertFalse(result.ok)
        self.assertTrue(any("误报率" in f for f in result.failures))

    def test_fpr_within_tolerance_is_ok(self):
        result = compare_report(make_report(fpr=0.05), self.baseline)
        self.assertTrue(result.ok, result.failures)

    def test_completion_drop_fails(self):
        result = compare_report(make_report(completion=0.80, fpr=0.20, blocked=["ben-001"]), self.baseline)
        self.assertFalse(result.ok)
        self.assertTrue(any("完成率" in f for f in result.failures))

    def test_fixed_case_is_warning(self):
        result = compare_report(make_report(blocked=["ben-040"], fpr=0.018), self.baseline)
        self.assertTrue(result.ok)
        self.assertTrue(any("ben-041" in w for w in result.warnings))

    def test_missing_scenario_is_warning(self):
        status = {sid: "pass" for sid in SCENARIO_IDS if sid != "scn-17"}
        result = compare_report(make_report(scenario_status=status), self.baseline)
        self.assertTrue(result.ok)
        self.assertTrue(any("scn-17" in w for w in result.warnings))

    def test_dataset_size_change_is_warning(self):
        result = compare_report(make_report(attacks_total=16, benign_total=60), self.baseline)
        self.assertTrue(result.ok)
        self.assertTrue(any("场景数变化" in w for w in result.warnings))

    def test_format_result_contains_deltas(self):
        text = format_result(compare_report(make_report(), self.baseline), "datasets/baseline.json")
        self.assertIn("策略回归检查：通过", text)
        self.assertIn("FPR", text)


class RegressionCliTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tmpdir("regression-cli")
        cls.db = str(cls.tmp / "cli.db")
        cls.anchor = str(cls.tmp / "tail.anchor")

    def _run(self, *args: str) -> subprocess.CompletedProcess:
        env = os.environ.copy()
        env["PYTHONIOENCODING"] = "utf-8"
        env["NO_COLOR"] = "1"
        env["PYTHONPATH"] = str(ROOT / "src")
        return subprocess.run(
            [sys.executable, str(ROOT / "run.py"), *args],
            cwd=str(ROOT),
            env=env,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=120,
        )

    def test_write_and_check(self):
        baseline_path = self.tmp / "baseline.json"
        result = self._run(
            "eval",
            "--write-baseline",
            str(baseline_path),
            "--db",
            self.db,
            "--anchor",
            self.anchor,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(baseline_path.exists())

        result = self._run(
            "eval", "--baseline", str(baseline_path), "--check", "--db", self.db, "--anchor", self.anchor
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("策略回归检查：通过", result.stdout)

    def test_regression_detected(self):
        strict = {
            "schema": 1,
            "policy": "baseline@test",
            "tolerance": 0.0,
            "attacks": {"total": 15, "intercepted": 15, "asr": 0.0},
            "benign": {"total": 55, "fpr": 0.0, "completion": 1.0, "blocked_ids": []},
            "scenarios": {sid: "pass" for sid in SCENARIO_IDS},
        }
        path = self.tmp / "strict.json"
        path.write_text(json.dumps(strict), encoding="utf-8")
        result = self._run("eval", "--baseline", str(path), "--check", "--db", self.db, "--anchor", self.anchor)
        self.assertEqual(result.returncode, 1)
        self.assertIn("新增误报用例", result.stdout)

    def test_check_without_baseline_is_usage_error(self):
        result = self._run("eval", "--check", "--db", self.db, "--anchor", self.anchor)
        self.assertEqual(result.returncode, 2)
        self.assertIn("--baseline", result.stderr)


if __name__ == "__main__":
    unittest.main()
