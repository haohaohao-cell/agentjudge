"""告警：通道报文、严重度过滤、限流、失败不阻断、与引擎集成。"""

from __future__ import annotations

import json
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from helpers import make_judge, tmpdir

from agentjudge.alerting import (
    AlertConfig,
    AlertEvent,
    AlertManager,
    EmailNotifier,
    MemoryNotifier,
    WebhookNotifier,
    build_alerting,
    decision_to_event,
)
from agentjudge.types import Action, Decision, Finding, Severity, ToolCall


class _HookHandler(BaseHTTPRequestHandler):
    received: list[dict] = []

    def log_message(self, *args):  # noqa: ANN002
        pass

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length)
        try:
            payload = json.loads(body.decode("utf-8"))
        except json.JSONDecodeError:
            payload = {"_raw": body.decode("utf-8", "replace")}
        _HookHandler.received.append({"path": self.path, "payload": payload})
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"{}")


class WebhookTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), _HookHandler)
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def setUp(self):
        _HookHandler.received.clear()

    def test_feishu_payload(self):
        notifier = WebhookNotifier(f"http://127.0.0.1:{self.port}/hook", "feishu")
        event = AlertEvent(kind="deny", title="拦截", detail="SHELL-RM-RF", risk=100)
        self.assertTrue(notifier.send(event))
        payload = _HookHandler.received[0]["payload"]
        self.assertEqual(payload["msg_type"], "text")
        self.assertIn("SHELL-RM-RF", payload["content"]["text"])

    def test_wecom_and_slack(self):
        WebhookNotifier(f"http://127.0.0.1:{self.port}/a", "wecom").send(AlertEvent("deny", "t", "d"))
        WebhookNotifier(f"http://127.0.0.1:{self.port}/b", "slack").send(AlertEvent("deny", "t", "d"))
        self.assertIn("msgtype", _HookHandler.received[0]["payload"])
        self.assertIn("text", _HookHandler.received[1]["payload"])

    def test_generic_payload_is_full_event(self):
        WebhookNotifier(f"http://127.0.0.1:{self.port}/c", "generic").send(
            AlertEvent("escalate", "待复核", "SHELL-SUDO", risk=30)
        )
        payload = _HookHandler.received[0]["payload"]
        self.assertEqual(payload["event"]["kind"], "escalate")
        self.assertEqual(payload["event"]["risk"], 30)

    def test_unreachable_endpoint_returns_false(self):
        notifier = WebhookNotifier("http://127.0.0.1:1/hook", "generic", timeout_s=0.3)
        self.assertFalse(notifier.send(AlertEvent("deny", "t", "d")))

    def test_invalid_type_rejected(self):
        with self.assertRaises(ValueError):
            WebhookNotifier("http://127.0.0.1/x", "irc")


class EmailTest(unittest.TestCase):
    def test_requires_recipients(self):
        with self.assertRaises(ValueError):
            EmailNotifier(host="smtp.example.com", recipients=[])

    def test_unreachable_smtp_returns_false(self):
        notifier = EmailNotifier(
            host="127.0.0.1", port=1, recipients=["a@b.c"], timeout_s=0.3, starttls=False
        )
        self.assertFalse(notifier.send(AlertEvent("deny", "t", "d")))

    def test_describe_hides_secrets(self):
        notifier = EmailNotifier(
            host="smtp.example.com",
            username="u",
            password="super-secret",
            recipients=["a@b.c", "d@e.f"],
        )
        described = notifier.describe()
        self.assertNotIn("super-secret", json.dumps(described))
        self.assertEqual(described["recipients"], 2)


class ConfigTest(unittest.TestCase):
    def test_min_rank(self):
        self.assertEqual(AlertConfig(min_severity="critical").min_rank, Severity.CRITICAL.rank)
        self.assertEqual(AlertConfig(min_severity="nonsense").min_rank, Severity.HIGH.rank)

    def test_public_snapshot_has_no_urls(self):
        cfg = AlertConfig(enabled=True, webhooks=[{"type": "feishu", "url": "https://secret/hook"}])
        snapshot = cfg.to_dict()
        self.assertNotIn("https://secret/hook", json.dumps(snapshot))
        self.assertTrue(snapshot["webhooks"][0]["configured"])

    def test_build_skips_unconfigured(self):
        manager = build_alerting(AlertConfig(enabled=True, webhooks=[{"type": "feishu", "url_env": "NOT_SET_XYZ"}]))
        self.assertEqual(manager.notifiers, [])
        self.assertFalse(manager.should_alert(Decision(session_id="s", tool="t", action=Action.DENY)))

    def test_build_from_env(self):
        import os

        os.environ["AJ_TEST_HOOK"] = "http://127.0.0.1:9/hook"
        try:
            manager = build_alerting(
                AlertConfig(enabled=True, webhooks=[{"type": "feishu", "url_env": "AJ_TEST_HOOK"}])
            )
            self.assertEqual(len(manager.notifiers), 1)
            self.assertEqual(manager.notifiers[0].kind, "feishu")
        finally:
            os.environ.pop("AJ_TEST_HOOK", None)


class ManagerTest(unittest.TestCase):
    def _decision(self, action: Action, severity: Severity = Severity.HIGH, quarantined: bool = False) -> Decision:
        return Decision(
            session_id="s1",
            tool="shell.exec",
            action=action,
            risk=60 if action is Action.DENY else 30,
            quarantined=quarantined,
            findings=[
                Finding(
                    guard="rules",
                    rule_id="TEST-1",
                    title="测试命中",
                    severity=severity,
                    action=action,
                )
            ],
        )

    def test_deny_is_alerted(self):
        memory = MemoryNotifier()
        manager = AlertManager(AlertConfig(enabled=True), [memory])
        try:
            self.assertTrue(manager.submit(self._decision(Action.DENY)))
            self.assertTrue(manager.flush(2.0))
            self.assertEqual(len(memory.events), 1)
            self.assertEqual(memory.events[0].kind, "deny")
        finally:
            manager.close()

    def test_allow_is_not_alerted(self):
        memory = MemoryNotifier()
        manager = AlertManager(AlertConfig(enabled=True), [memory])
        try:
            self.assertFalse(manager.submit(self._decision(Action.ALLOW)))
            manager.flush(1.0)
            self.assertEqual(memory.events, [])
        finally:
            manager.close()

    def test_min_severity_filters(self):
        memory = MemoryNotifier()
        manager = AlertManager(AlertConfig(enabled=True, min_severity="critical"), [memory])
        try:
            self.assertFalse(manager.submit(self._decision(Action.DENY, Severity.HIGH)))
            self.assertTrue(manager.submit(self._decision(Action.DENY, Severity.CRITICAL)))
            manager.flush(2.0)
            self.assertEqual(len(memory.events), 1)
        finally:
            manager.close()

    def test_quarantine_alerted(self):
        memory = MemoryNotifier()
        manager = AlertManager(AlertConfig(enabled=True), [memory])
        try:
            manager.submit(self._decision(Action.ALLOW, Severity.CRITICAL, quarantined=True))
            self.assertTrue(manager.flush(2.0))
            self.assertEqual(memory.events[0].kind, "quarantine")
        finally:
            manager.close()

    def test_rate_limit_drops(self):
        memory = MemoryNotifier()
        manager = AlertManager(AlertConfig(enabled=True, rate_limit_per_min=1), [memory])
        try:
            accepted = [manager.submit(self._decision(Action.DENY)) for _ in range(4)]
            self.assertEqual(accepted.count(True), 1)
            self.assertEqual(manager.dropped, 3)
        finally:
            manager.close()

    def test_disabled_manager_does_nothing(self):
        memory = MemoryNotifier()
        manager = AlertManager(AlertConfig(enabled=False), [memory])
        try:
            self.assertFalse(manager.submit(self._decision(Action.DENY)))
        finally:
            manager.close()

    def test_decision_to_event_text(self):
        decision = self._decision(Action.DENY)
        decision.reasons = [
            {"rule_id": "TEST-1", "title": "测试命中", "severity": "high", "action": "deny", "guard": "rules"}
        ]
        event = decision_to_event(decision)
        self.assertIn("TEST-1", event.text())
        self.assertEqual(event.severity, "high")

    def test_decision_to_event_falls_back_to_findings(self):
        event = decision_to_event(self._decision(Action.DENY))
        self.assertIn("TEST-1", event.detail)


class JudgeIntegrationTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tmpdir("alert-int")
        self.judge = make_judge(self.tmp)
        self.memory = MemoryNotifier()
        self.manager = AlertManager(AlertConfig(enabled=True), [self.memory])
        self.judge.alerts = self.manager

    def tearDown(self):
        self.manager.close()
        self.judge.close()

    def test_deny_triggers_alert(self):
        self.judge.intercept(ToolCall(tool="shell.exec", args={"command": "rm -rf /"}, session_id="al"))
        self.assertTrue(self.manager.flush(2.0))
        self.assertEqual(len(self.memory.events), 1)
        self.assertEqual(self.memory.events[0].tool, "shell.exec")

    def test_benign_does_not_alert(self):
        self.judge.intercept(ToolCall(tool="shell.exec", args={"command": "ls"}, session_id="al2"))
        self.manager.flush(1.0)
        self.assertEqual(self.memory.events, [])

    def test_alert_failure_never_breaks_decision(self):
        class Boom(MemoryNotifier):
            def send(self, event):
                raise RuntimeError("boom")

        self.manager.notifiers = [Boom()]
        decision = self.judge.intercept(
            ToolCall(tool="shell.exec", args={"command": "rm -rf /"}, session_id="al3")
        )
        self.assertIs(decision.action, Action.DENY)
        self.manager.flush(1.0)
        stats = self.judge.stats()["alerting"]
        self.assertGreaterEqual(stats["failed"], 1)


if __name__ == "__main__":
    unittest.main()
