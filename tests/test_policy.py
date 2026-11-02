"""策略解析与校验。"""

from __future__ import annotations

import unittest

from helpers import ROOT, tmpdir

from agentjudge.errors import PolicyError
from agentjudge.policy import Policy
from agentjudge.types import Action

POLICY = ROOT / "policies" / "default.toml"


class PolicyTest(unittest.TestCase):
    def test_loads_default_policy(self):
        policy = Policy.load(POLICY, base_dir=ROOT)
        self.assertEqual(policy.mode, "enforce")
        self.assertGreaterEqual(len(policy.rules), 25)
        self.assertTrue(policy.guard("canary").enabled)
        self.assertEqual(policy.thresholds["deny_at"], 70)

    def test_rule_ids_are_unique(self):
        policy = Policy.load(POLICY, base_dir=ROOT)
        ids = [r.id for r in policy.rules]
        self.assertEqual(len(ids), len(set(ids)))

    def test_every_rule_has_explanation(self):
        policy = Policy.load(POLICY, base_dir=ROOT)
        for rule in policy.rules:
            self.assertTrue(rule.explain, f"{rule.id} 缺少 explain")

    def test_fail_closed_cannot_allow(self):
        with self.assertRaises(PolicyError):
            Policy.from_mapping({"fail_closed_action": "allow"})

    def test_invalid_mode_rejected(self):
        with self.assertRaises(PolicyError):
            Policy.from_mapping({"mode": "yolo"})

    def test_thresholds_validated(self):
        with self.assertRaises(PolicyError):
            Policy.from_mapping({"thresholds": {"escalate_at": 80, "deny_at": 20}})

    def test_duplicate_rule_ids_rejected(self):
        rule = {"id": "X", "title": "x", "pattern": "x", "severity": "low", "action": "deny"}
        with self.assertRaises(PolicyError):
            Policy.from_mapping({"rules": [rule, dict(rule)]})

    def test_bad_regex_rejected(self):
        with self.assertRaises(PolicyError):
            Policy.from_mapping(
                {"rules": [{"id": "bad", "title": "bad", "pattern": "([", "action": "deny"}]}
            )

    def test_watcher_provider_validated(self):
        with self.assertRaises(PolicyError):
            Policy.from_mapping({"watcher": {"provider": "skynet"}})

    def test_extends_inheritance(self):
        tmp = tmpdir("policy-extend")
        (tmp / "base.toml").write_text(
            "schema = 1\nname = 'base'\nmode = 'enforce'\n[[rules]]\n"
            "id = 'R1'\ntitle = 'r1'\npattern = 'abc'\nseverity = 'low'\naction = 'deny'\n",
            encoding="utf-8",
        )
        (tmp / "child.toml").write_text(
            "extend = 'base.toml'\nname = 'child'\nmode = 'monitor'\n", encoding="utf-8"
        )
        policy = Policy.load(tmp / "child.toml", base_dir=tmp)
        self.assertEqual(policy.name, "child")
        self.assertEqual(policy.mode, "monitor")
        self.assertEqual([r.id for r in policy.rules], ["R1"])

    def test_extends_cycle_detected(self):
        tmp = tmpdir("policy-cycle")
        (tmp / "a.toml").write_text("extend = 'b.toml'\n", encoding="utf-8")
        (tmp / "b.toml").write_text("extend = 'a.toml'\n", encoding="utf-8")
        with self.assertRaises(PolicyError):
            Policy.load(tmp / "a.toml", base_dir=tmp)

    def test_monitor_policy(self):
        policy = Policy.load(ROOT / "policies" / "monitor.toml", base_dir=ROOT)
        self.assertEqual(policy.mode, "monitor")
        self.assertGreaterEqual(len(policy.rules), 25)

    def test_public_snapshot_hides_key_material(self):
        policy = Policy.load(POLICY, base_dir=ROOT)
        public = policy.public()
        self.assertNotIn("key_file", public["audit"] if "audit" in public else {})
        self.assertEqual(public["mode"], "enforce")
        self.assertEqual(public["fail_closed_action"], Action.DENY.value)


if __name__ == "__main__":
    unittest.main()
