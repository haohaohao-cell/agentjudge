"""防篡改审计链：正常链路、篡改检测、尾锚、取证导出与回放。"""

from __future__ import annotations

import json
import sqlite3
import unittest
import zipfile

from helpers import make_judge, tmpdir

from agentjudge.audit.chain import GENESIS
from agentjudge.types import ToolCall
from agentjudge.utils import canonical_json


class AuditChainTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tmpdir()
        self.judge = make_judge(self.tmp)
        self.store = self.judge.store
        for index in range(5):
            self.judge.intercept(
                ToolCall(tool="shell.exec", args={"command": f"echo {index}"}, session_id="a")
            )

    def tearDown(self):
        try:
            self.judge.close()
        except Exception:
            pass

    # -- 正常 -------------------------------------------------------------
    def test_chain_grows_and_verifies(self):
        self.assertEqual(self.store.count(), 5)
        result = self.store.verify()
        self.assertTrue(result.ok)
        self.assertEqual(result.records, 5)
        self.assertEqual(result.first_seq, 1)
        self.assertEqual(result.last_seq, 5)

    def test_records_are_linked(self):
        records = list(self.store.iter_records())
        self.assertEqual(records[0].prev, GENESIS)
        for previous, current in zip(records, records[1:]):
            self.assertEqual(current.prev, previous.current)

    def test_seal_writes_anchor(self):
        state = self.store.seal(force=True)
        self.assertIsNotNone(state)
        self.assertTrue((self.tmp / "tail.anchor").exists())
        result = self.store.verify()
        self.assertTrue(result.anchor_present)
        self.assertTrue(result.anchor_matches)

    def test_export_bundle(self):
        path = self.store.export_bundle(self.tmp / "evidence.zip", policy_snapshot={"name": "t"})
        self.assertTrue(path.exists())
        with zipfile.ZipFile(path) as zf:
            names = set(zf.namelist())
            self.assertIn("records.jsonl", names)
            self.assertIn("verify.json", names)
            self.assertIn("README.txt", names)
            first = zf.read("records.jsonl").decode("utf-8").splitlines()[0]
            self.assertEqual(json.loads(first)["seq"], 1)

    # -- 篡改 -------------------------------------------------------------
    def _exec(self, sql: str, params: tuple = ()) -> None:
        conn = sqlite3.connect(self.store.db_path)
        try:
            conn.execute(sql, params)
            conn.commit()
        finally:
            conn.close()

    def test_modified_payload_detected(self):
        self._exec("UPDATE audit_records SET payload=? WHERE seq=2", (canonical_json({"x": 1}),))
        result = self.store.verify()
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "hash_mismatch")
        self.assertEqual(result.broken_at, 2)

    def test_deleted_tail_detected(self):
        self._exec("DELETE FROM audit_records WHERE seq=5")
        result = self.store.verify()
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "tail_mismatch")

    def test_replaced_tail_record_detected(self):
        conn = sqlite3.connect(self.store.db_path)
        try:
            row = conn.execute("SELECT payload, current FROM audit_records WHERE seq=4").fetchone()
        finally:
            conn.close()
        # 把第 5 条替换成第 4 条的内容，并保持 prev 正确（链不断），只能靠 HMAC 检出
        self._exec(
            "UPDATE audit_records SET payload=?, current=?, prev=? WHERE seq=5",
            (row[0], row[1], row[1]),
        )
        result = self.store.verify()
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "hash_mismatch")

    def test_truncated_history_detected_by_anchor(self):
        self.store.seal(force=True)
        self._exec("DELETE FROM audit_records")
        self._exec(
            "UPDATE chain_tail SET chain_tail=?, tail_count=0, hmac_tail=? WHERE id=1",
            (GENESIS, self.store.keyring.hmac_tail(GENESIS, 0)),
        )
        result = self.store.verify()
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "anchor_mismatch")

    def test_forged_anchor_detected(self):
        self.store.seal(force=True)
        path = self.tmp / "tail.anchor"
        data = json.loads(path.read_text(encoding="utf-8"))
        data["chain_tail"] = "f" * 64
        path.write_text(json.dumps(data), encoding="utf-8")
        result = self.store.verify()
        self.assertFalse(result.ok)

    def test_key_change_breaks_verification(self):
        from agentjudge.audit.chain import Keyring

        other = Keyring(b"a-different-key-0123456789abcdef")
        self.store.keyring = other
        result = self.store.verify()
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "hash_mismatch")

    # -- 回放 -------------------------------------------------------------
    def test_hydrate_rebuilds_sessions(self):
        self.judge.sessions.clear()
        restored = self.judge.hydrate(limit=100)
        self.assertEqual(restored, 5)
        session = self.judge.sessions.get("a")
        self.assertIsNotNone(session)
        self.assertEqual(len(session.steps), 5)


if __name__ == "__main__":
    unittest.main()
