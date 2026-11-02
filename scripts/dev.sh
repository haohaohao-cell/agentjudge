#!/usr/bin/env bash
# 本地开发入口：启动服务并打开工作台
set -euo pipefail
cd "$(dirname "$0")/.."
export PYTHONPATH="${PWD}/src:${PYTHONPATH:-}"
export PYTHONIOENCODING=utf-8
PORT="${1:-8737}"
exec python -m agentjudge serve --host 127.0.0.1 --port "${PORT}"
