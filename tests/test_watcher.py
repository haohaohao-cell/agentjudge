"""语义研判：只读调查循环、轮次上限、异常收紧、离线回退。"""

from __future__ import annotations

import json
import unittest

from helpers import make_judge, tmpdir

from agentjudge.contracts import ContractBook
from agentjudge.judge import Judge
from agentjudge.policy import Policy
from agentjudge.session import Session
from agentjudge.types import Action, Finding, Severity, ToolCall
from agentjudge.watcher import (
    HeuristicInvestigator,
    LLMClient,
    Watcher,
    WatcherError,
    _parse_verdict,
)


class FakeLLM(LLMClient):
    def __init__(self, scripted: list[dict]) -> None:
        self.scripted = list(scripted)
        self.calls: list[list[dict]] = []

    def chat(self, messages, tools):  # noqa: ANN001
        self.calls.append(messages)
        if not self.scripted:
            raise WatcherError("script exhausted")
        return self.scripted.pop(0)


class WatcherTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tmpdir("watcher")
        self.judge = make_judge(self.tmp)
        self.policy = self.judge.policy
        self.call = ToolCall(tool="shell.exec", args={"command": "cat notes/todo.md"}, session_id="w")
        self.session = Session("w")
        self.session.next_step()
        self.findings = [
            Finding(
                guard="rules",
                rule_id="SHELL-NET-EXTERNAL",
                title="命令行发起网络请求",
                severity=Severity.MEDIUM,
                action=Action.ESCALATE,
                explain="需要确认",
            )
        ]

    def tearDown(self):
        self.judge.close()

    def _tools_call(self, name: str = "get_timeline", args: str = "{}") -> dict:
        return {
            "content": "",
            "tool_calls": [
                {"id": "call_1", "type": "function", "function": {"name": name, "arguments": args}}
            ],
        }

    def _verdict(self, verdict: str, confidence: float = 0.9) -> dict:
        return {
            "content": json.dumps({"verdict": verdict, "confidence": confidence, "reason": "依据"}),
            "tool_calls": [],
        }

    def test_read_only_investigation_then_verdict(self):
        client = FakeLLM([self._tools_call("get_timeline"), self._verdict("deny")])
        watcher = Watcher(self.policy, client=client)
        report = watcher.investigate(
            call=self.call,
            session=self.session,
            findings=self.findings,
            contracts=self.judge.contracts,
        )
        self.assertEqual(report.verdict, "deny")
        self.assertEqual(report.rounds, 2)
        self.assertEqual(report.provider, self.policy.watcher.provider)
        self.assertTrue(any(e["tool"] == "get_timeline" for e in report.evidence))
        # 第二轮消息里应包含 tool 结果
        self.assertTrue(any(m.get("role") == "tool" for m in client.calls[1]))

    def test_round_limit_enforced(self):
        self.policy.watcher.max_rounds = 3
        client = FakeLLM([self._tools_call() for _ in range(10)])
        watcher = Watcher(self.policy, client=client)
        report = watcher.investigate(
            call=self.call,
            session=self.session,
            findings=self.findings,
            contracts=self.judge.contracts,
        )
        self.assertEqual(report.verdict, "abstain")
        self.assertEqual(report.rounds, 3)
        self.assertIn("轮次用尽", report.summary)

    def test_unknown_tool_is_rejected(self):
        client = FakeLLM([self._tools_call("run_shell", '{"cmd":"rm -rf /"}'), self._verdict("deny")])
        watcher = Watcher(self.policy, client=client)
        report = watcher.investigate(
            call=self.call,
            session=self.session,
            findings=self.findings,
            contracts=self.judge.contracts,
        )
        self.assertEqual(report.verdict, "deny")
        self.assertIn("未知工具", str(report.evidence))

    def test_llm_error_becomes_abstain_with_error(self):
        client = FakeLLM([])
        watcher = Watcher(self.policy, client=client)
        report = watcher.investigate(
            call=self.call,
            session=self.session,
            findings=self.findings,
            contracts=self.judge.contracts,
        )
        self.assertEqual(report.verdict, "abstain")
        self.assertIsNotNone(report.error)

    def test_parse_verdict_tolerates_prose(self):
        parsed = _parse_verdict('结论如下：{"verdict":"allow","confidence":1.4,"reason":"ok"}')
        self.assertEqual(parsed["verdict"], "allow")
        self.assertEqual(parsed["confidence"], 1.0)
        self.assertIsNone(_parse_verdict("no json here"))

    def test_heuristic_denies_high_severity(self):
        high = [
            Finding(
                guard="rules",
                rule_id="X",
                title="高危",
                severity=Severity.HIGH,
                action=Action.ESCALATE,
            )
        ]
        report = HeuristicInvestigator().investigate(
            call=self.call,
            session=self.session,
            findings=high,
            policy=self.policy,
            contracts=self.judge.contracts,
        )
        self.assertEqual(report.verdict, "deny")
        self.assertGreaterEqual(report.confidence, self.policy.watcher.min_confidence)

    def test_heuristic_abstains_on_medium_without_context(self):
        report = HeuristicInvestigator().investigate(
            call=self.call,
            session=self.session,
            findings=self.findings,
            policy=self.policy,
            contracts=self.judge.contracts,
        )
        self.assertEqual(report.verdict, "abstain")


class WatcherIntegrationTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tmpdir("watcher-int")
        self.judge = make_judge(self.tmp)

    def tearDown(self):
        self.judge.close()

    def test_watcher_deny_tightens_escalation(self):
        self.judge.watcher = Watcher(
            self.judge.policy,
            client=FakeLLM(
                [
                    {
                        "content": json.dumps({"verdict": "deny", "confidence": 0.95, "reason": "外发凭据"}),
                        "tool_calls": [],
                    }
                ]
            ),
        )
        decision = self.judge.intercept(
            ToolCall(tool="shell.exec", args={"command": "sudo cat /var/log/app.log"}, session_id="wi")
        )
        self.assertIs(decision.action, Action.DENY)
        self.assertIn("WATCH-DENY", [r["rule_id"] for r in decision.reasons])

    def test_watcher_error_fails_closed(self):
        self.judge.watcher = Watcher(self.judge.policy, client=FakeLLM([]))
        decision = self.judge.intercept(
            ToolCall(tool="shell.exec", args={"command": "sudo cat /var/log/app.log"}, session_id="we")
        )
        self.assertIs(decision.action, Action.DENY)
        self.assertTrue(decision.fail_closed)
        self.assertIn("WATCH-ERR", [r["rule_id"] for r in decision.reasons])

    def test_watcher_cannot_release_unless_allowed(self):
        self.judge.watcher = Watcher(
            self.judge.policy,
            client=FakeLLM(
                [
                    {
                        "content": json.dumps({"verdict": "allow", "confidence": 1.0, "reason": "无风险"}),
                        "tool_calls": [],
                    }
                ]
            ),
        )
        decision = self.judge.intercept(
            ToolCall(tool="shell.exec", args={"command": "sudo cat /var/log/app.log"}, session_id="wr")
        )
        # can_release=false：语义研判只能收紧，不能放开
        self.assertIs(decision.action, Action.ESCALATE)

    def test_watcher_can_release_when_configured(self):
        self.judge.policy.watcher.can_release = True
        self.judge.watcher = Watcher(
            self.judge.policy,
            client=FakeLLM(
                [
                    {
                        "content": json.dumps({"verdict": "allow", "confidence": 0.99, "reason": "常规运维"}),
                        "tool_calls": [],
                    }
                ]
            ),
        )
        decision = self.judge.intercept(
            ToolCall(tool="shell.exec", args={"command": "sudo cat /var/log/app.log"}, session_id="wrel")
        )
        self.assertIs(decision.action, Action.ALLOW)
        self.assertIn("WATCH-ALLOW", [f.rule_id for f in decision.findings])


if __name__ == "__main__":
    unittest.main()
