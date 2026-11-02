#!/usr/bin/env bash
# 一键演示：外泄链拦截 + 审计链校验
set -euo pipefail
cd "$(dirname "$0")/.."
export PYTHONPATH="${PWD}/src:${PYTHONPATH:-}"
export PYTHONIOENCODING=utf-8
python -m agentjudge demo
python -m agentjudge audit verify
