"""LLM 客户端与 Watcher 的真实 HTTP 路径（本地 mock，不访问外网）。"""

from __future__ import annotations

import json
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from helpers import make_judge, tmpdir

from agentjudge.contracts import ContractBook
from agentjudge.session import Session
from agentjudge.types import Action, Finding, Severity, ToolCall
from agentjudge.watcher import OpenAICompatClient, Watcher, WatcherError


class _MockLLM(BaseHTTPRequestHandler):
    mode = "ok"
    tool_rounds = 0
    requests: list[dict] = []

    def log_message(self, *args):  # noqa: ANN002
        pass

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length") or 0)
        body = json.loads(self.rfile.read(length).decode("utf-8"))
        _MockLLM.requests.append(
            {"path": self.path, "auth": self.headers.get("Authorization", ""), "body": body}
        )
        mode = _MockLLM.mode
        if _MockLLM.tool_rounds > 0:
            _MockLLM.tool_rounds -= 1
            mode = "tool"
        if mode == "error":
            self.send_response(500)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if mode == "badjson":
            payload = b"not-json"
        elif mode == "tool":
            payload = json.dumps(
                {
                    "choices": [
                        {
                            "message": {
                                "content": "",
                                "tool_calls": [
                                    {
                                        "id": "call_1",
                                        "type": "function",
                                        "function": {"name": "get_timeline", "arguments": "{}"},
                                    }
                                ],
                            }
                        }
                    ]
                }
            ).encode()
        else:
            payload = json.dumps(
                {
                    "choices": [
                        {
                            "message": {
                                "content": json.dumps(
                                    {"verdict": "deny", "confidence": 0.93, "reason": "外发凭据"}
                                )
                            }
                        }
                    ]
                }
            ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


class LLMClientTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), _MockLLM)
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def setUp(self):
        _MockLLM.mode = "ok"
        _MockLLM.tool_rounds = 0
        _MockLLM.requests.clear()

    def _client(self, timeout: float = 3.0) -> OpenAICompatClient:
        return OpenAICompatClient(
            base_url=f"http://127.0.0.1:{self.port}/v1", model="mock-model", api_key="sk-test", timeout_s=timeout
        )

    def test_sends_expected_request(self):
        client = self._client()
        reply = client.chat([{"role": "user", "content": "hi"}], None)
        self.assertEqual(reply["content"], json.dumps({"verdict": "deny", "confidence": 0.93, "reason": "外发凭据"}))
        request = _MockLLM.requests[0]
        self.assertEqual(request["path"], "/v1/chat/completions")
        self.assertEqual(request["auth"], "Bearer sk-test")
        self.assertEqual(request["body"]["model"], "mock-model")
        self.assertNotIn("tools", request["body"])

    def test_tools_are_passed_through(self):
        tools = [{"type": "function", "function": {"name": "x", "parameters": {}}}]
        self._client().chat([{"role": "user", "content": "hi"}], tools)
        self.assertEqual(_MockLLM.requests[0]["body"]["tool_choice"], "auto")
        self.assertEqual(_MockLLM.requests[0]["body"]["tools"], tools)

    def test_tool_calls_parsed(self):
        _MockLLM.mode = "tool"
        reply = self._client().chat([{"role": "user", "content": "hi"}], [])
        self.assertEqual(reply["tool_calls"][0]["function"]["name"], "get_timeline")

    def test_http_error_raises(self):
        _MockLLM.mode = "error"
        with self.assertRaises(WatcherError):
            self._client().chat([{"role": "user", "content": "hi"}], None)

    def test_bad_json_raises(self):
        _MockLLM.mode = "badjson"
        with self.assertRaises(WatcherError):
            self._client().chat([{"role": "user", "content": "hi"}], None)

    def test_connection_refused_raises(self):
        client = OpenAICompatClient(
            base_url="http://127.0.0.1:1/v1", model="m", api_key="k", timeout_s=0.3
        )
        with self.assertRaises(WatcherError):
            client.chat([{"role": "user", "content": "hi"}], None)


class WatcherOverHTTPTest(unittest.TestCase):
    """走真实 urllib 的 2 轮调查循环。"""

    @classmethod
    def setUpClass(cls):
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), _MockLLM)
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        cls.tmp = tmpdir("watcher-http")
        cls.judge = make_judge(cls.tmp)

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.judge.close()

    def setUp(self):
        _MockLLM.mode = "ok"
        _MockLLM.tool_rounds = 0
        _MockLLM.requests.clear()

    def test_two_rounds_then_deny(self):
        _MockLLM.tool_rounds = 1
        client = OpenAICompatClient(
            base_url=f"http://127.0.0.1:{self.port}/v1", model="m", api_key="k", timeout_s=3.0
        )
        watcher = Watcher(self.judge.policy, client=client)
        session = Session("http-int")
        session.next_step()
        call = ToolCall(tool="shell.exec", args={"command": "cat notes/todo.md"}, session_id="http-int")
        findings = [
            Finding(
                guard="rules",
                rule_id="SHELL-NET-EXTERNAL",
                title="出网",
                severity=Severity.MEDIUM,
                action=Action.ESCALATE,
            )
        ]
        report = watcher.investigate(
            call=call,
            session=session,
            findings=findings,
            contracts=ContractBook.load_dir(self.judge.policy.resolve("contracts"), str(self.tmp)),
        )
        self.assertEqual(report.verdict, "deny")
        self.assertEqual(report.rounds, 2)
        self.assertGreaterEqual(len(_MockLLM.requests), 2)
        self.assertEqual(report.provider, self.judge.policy.watcher.provider)


if __name__ == "__main__":
    unittest.main()
