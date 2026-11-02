"""框架适配器。

设计原则：**旁路接入**。适配器只挂在被监督方的工具调用钩子上，
不要求改动其核心逻辑，也不接管进程权限。
"""

from __future__ import annotations

from .mcp import MCPGuard, mcp_tools_call
from .openclaw import PointerPlugin

__all__ = ["MCPGuard", "PointerPlugin", "mcp_tools_call"]
