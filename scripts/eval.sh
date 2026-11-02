#!/usr/bin/env bash
# 运行完整评测并输出 Markdown 报告
set -euo pipefail
cd "$(dirname "$0")/.."
export PYTHONPATH="${PWD}/src:${PYTHONPATH:-}"
export PYTHONIOENCODING=utf-8
mkdir -p var/reports
python -m agentjudge eval --report "var/reports/eval-$(date +%Y%m%d-%H%M%S).json"
