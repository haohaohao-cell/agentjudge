#!/bin/sh
# 容器入口：强制要求 Token（监听 0.0.0.0 时不允许无鉴权）
set -eu

: "${AGENTJUDGE_TOKEN:?必须设置 AGENTJUDGE_TOKEN（工作台与 API 的 Bearer Token）}"
: "${PORT:=8737}"

exec agentjudge serve --host 0.0.0.0 --port "${PORT}" --token "${AGENTJUDGE_TOKEN}"
