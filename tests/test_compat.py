"""Windows 兼容性：UTF-8 BOM 的策略/合约/清单必须能正常加载。"""

from __future__ import annotations

import unittest

from helpers import ROOT, tmpdir

from agentjudge.contracts import ContractBook
from agentjudge.policy import Policy
from agentjudge.skillcheck import inspect_skill

BOM = "\ufeff"

POLICY_BODY = """schema = 1
name = "bom-test"
mode = "enforce"
[[rules]]
id = "BOM-1"
title = "bom rule"
pattern = 'rm -rf'
severity = "high"
action = "deny"
"""

CONTRACT_BODY = """[tool]
name = "test.tool"
kind = "fs_read"

[paths]
allow_read = ["./**"]
"""


class BomTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tmpdir("bom")

    def test_policy_with_bom(self):
        path = self.tmp / "policy.toml"
        path.write_bytes((BOM + POLICY_BODY).encode("utf-8"))
        policy = Policy.load(path, base_dir=self.tmp)
        self.assertEqual(policy.name, "bom-test")
        self.assertEqual(len(policy.rules), 1)

    def test_contract_with_bom(self):
        (self.tmp / "contracts").mkdir()
        path = self.tmp / "contracts" / "test.toml"
        path.write_bytes((BOM + CONTRACT_BODY).encode("utf-8"))
        book = ContractBook.load_dir(self.tmp / "contracts", str(self.tmp))
        self.assertIsNotNone(book.for_tool("test.tool"))

    def test_skill_manifest_with_bom(self):
        skill = self.tmp / "skill"
        skill.mkdir()
        (skill / "skill.toml").write_bytes(
            (BOM + 'name = "bom-skill"\nversion = "1.0.0"\ndescription = "读取文件"\n').encode("utf-8")
        )
        report = inspect_skill(skill)
        self.assertEqual(report.name, "bom-skill")

    def test_crlf_policy_still_loads(self):
        path = self.tmp / "crlf.toml"
        path.write_bytes(POLICY_BODY.replace("\n", "\r\n").encode("utf-8"))
        policy = Policy.load(path, base_dir=self.tmp)
        self.assertEqual(policy.mode, "enforce")


if __name__ == "__main__":
    unittest.main()
