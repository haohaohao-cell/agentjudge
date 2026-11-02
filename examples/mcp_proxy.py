"""示例：在 MCP 客户端与服务端之间插入守卫。

真实部署时，把 ``guard.before_request`` / ``guard.after_response`` 串进你的
MCP 代理（进程内或 HTTP），无需修改 MCP Server。

运行：python examples/mcp_proxy.py
"""

from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from agentjudge import Judge  # noqa: E402
from agentjudge.adapters.mcp import MCPGuard, mcp_tools_call  # noqa: E402


def main() -> None:
    judge = Judge.from_policy("policies/default.toml")
    guard = MCPGuard(judge, session_id="mcp-demo")
    requests = [
        mcp_tools_call("fs.read", {"path": "README.md"}, call_id=1),
        mcp_tools_call("fs.read", {"path": "~/.ssh/id_rsa"}, call_id=2),
        mcp_tools_call("shell.exec", {"command": "nohup python3 backdoor.py &"}, call_id=3),
    ]
    try:
        for request in requests:
            name = request["params"]["name"]
            blocked = guard.before_request(request)
            print(f"{name} {request['params']['arguments']}")
            if blocked:
                print("  -> 拦截：", json.dumps(blocked["error"], ensure_ascii=False)[:160])
                continue
            print("  -> 放行，交给 MCP Server 执行")
            # 模拟服务端返回
            response = {"jsonrpc": "2.0", "id": request["id"], "result": {"content": [{"type": "text", "text": "ok"}]}}
            replaced = guard.after_response(request, response)
            if replaced:
                print("  -> 结果被隔离：", replaced["error"]["message"])
    finally:
        judge.close()


if __name__ == "__main__":
    main()
