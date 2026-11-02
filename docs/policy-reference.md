# 策略与合约参考

策略是 TOML 文件，默认 `policies/default.toml`。所有相对路径相对于**启动目录**解析。
加载后不可变（除测试与灰度场景显式修改）。

## 1. 顶层字段

| 字段 | 类型 | 默认 | 说明 |
| --- | --- | --- | --- |
| `schema` | int | 1 | 策略结构版本，高于程序支持版本会报错 |
| `name` | str | `baseline` | 策略名，出现在裁决与审计中 |
| `version` | str | `0.1.0` | 策略版本，用于追溯 |
| `mode` | str | `enforce` | `enforce` 拦截 / `monitor` 只记录 |
| `fail_closed_action` | str | `deny` | 守卫异常/研判失败时的动作，**不允许 `allow`** |
| `workspace_root` | str | `"."` | 工作区根，合约里的 `{{workspace}}` 会替换为它 |
| `contracts_dir` | str | `contracts` | 合约目录 |
| `extend` | str | — | 继承另一个策略文件（深度合并，子覆盖父） |

### 阈值

```toml
[thresholds]
escalate_at = 30   # 风险分达到 30 至少转人工
deny_at = 70       # 达到 70 直接拒绝
```

风险分 = 所有「会干预」的命中项严重度权重之和 + 5 ×（命中数 - 1），上限 100。
权重：`info=0, low=10, medium=30, high=60, critical=100`。
纯记录型命中（`action = "allow"`）不计分。

阈值只能**收紧**动作：`escalate` 累积超过 `deny_at` 会升级为 `deny`。

## 2. 网络

```toml
[network]
allow_hosts = ["github.com", "api.github.com", "docs.python.org", "pypi.org"]
internal_hosts = ["localhost", "127.0.0.1", "::1", "*.internal", "*.local", "10.*"]
```

支持 `*.example.com`、`10.*` 通配。规则里设 `unless_host_allowed = true` 时，
若命令/URL 中所有主机都在白名单内，该规则不触发（例如 `curl https://docs.python.org/`）。

## 3. 守卫

```toml
[guards.canary]
enabled = true
auto_canary = true          # 会话自动生成蜜标

[guards.stego]
enabled = true
max_scan_chars = 200000
base64_min_len = 64
entropy_threshold = 3.6

[guards.contract]
enabled = true
unknown_tool = "allow"      # allow | escalate | deny

[guards.rules]
enabled = true
quarantine_results = true   # 读取到注入指令时隔离

[guards.dataflow]
enabled = true
report_write_flows = true   # 敏感数据落盘只记录不阻断
```

## 4. 语义研判

```toml
[watcher]
enabled = true
provider = "none"           # none | openai | openai_compat | ollama
base_url = "https://api.openai.com/v1"
model = "gpt-4o-mini"
api_key_env = "AGENTJUDGE_LLM_KEY"
max_rounds = 8              # 只读调查轮次上限（硬上限 32）
timeout_s = 20.0
min_confidence = 0.75
can_release = false         # 模型能否把「转人工」改为「放行」
on_error = "deny"           # deny | escalate
max_evidence = 8
```

`provider = "none"` 或未设置密钥时，使用离线启发式研判（`HeuristicInvestigator`）：
高危 → 拒绝；仅低危 → 放行建议；中危且会话持有敏感数据 → 拒绝；其余 → 维持转人工。

## 5. 审计

```toml
[audit]
db_path = "var/agentjudge.db"
anchor_path = "var/tail.anchor"
key_file = "var/hmac.key"
key_env = "AGENTJUDGE_HMAC_KEY"   # 优先于 key_file
key_id = "k1"
seal_interval_s = 300
```

## 6. 规则

```toml
[[rules]]
id = "SHELL-PIPE-SH"              # 唯一，出现在审计与工作台
title = "远程脚本管道执行"
pattern = '\b(?:curl|wget|http|xh)\b[^\n|;]*\|\s*(?:sudo\s+)?(?:ba|z|k|da)?sh\b'
severity = "critical"             # info | low | medium | high | critical
action = "deny"                   # allow | escalate | deny
targets = ["command"]             # command/path/url/content/tool/arg.*/all
unless_host_allowed = false       # 命中白名单主机时跳过
explain = "curl | bash 等于把远端任意代码直接交给解释器。"
tags = ["rce", "supply_chain"]
enabled = true
```

### targets 取值

| 目标 | 匹配对象 |
| --- | --- |
| `command` | `args["command"/"cmd"/"script"]` |
| `path` | `args["path"/"file"/"filename"/"target"]` |
| `url` | `args["url"/"endpoint"/"uri"]` |
| `content` | `call.content`（读取到的内容） |
| `arg.*` | 所有字符串参数 |
| `tool` | 工具名 |
| `all` | 以上全部 |

匹配是 `re.search` + `IGNORECASE | MULTILINE`；同时尝试去掉零宽/标签字符后的归一化视图。

### 现有 31 条规则（按 ID 前缀）

- `SHELL-*`：删除、磁盘破坏、擦除、反弹 shell、`curl|bash`、编码执行、`nohup`、启动项、cron、`0.0.0.0`、`printenv`、`chmod 777`、`sudo`、历史清除、内联解释器、出网命令、下载即执行。
- `FS-*`：SSH 私钥、系统账号文件、云凭据、`.env`、shell 启动文件、系统目录写入、路径穿越。
- `INJ-*`：忽略既有指令、免审批、角色劫持、HTML 隐藏、诱导外发。
- `NET-*`：云元数据、粘贴/隧道服务。

`agentjudge rules list` 可查看全部；`agentjudge rules test "<文本>"` 可试跑。

## 7. 工具合约

`contracts/<tool>.toml`：

```toml
[tool]
name = "shell.exec"
kind = "shell"                                  # fs_read/fs_write/shell/network/email/memory
match = ["bash", "exec", "run_command"]         # 别名，按通配匹配
description = "在主机上执行命令"

[paths]
allow_read = ["./**", "{{workspace}}/**", "/tmp/**"]
deny_read = ["~/.ssh/**", "**/.env"]
allow_write = ["./**", "/tmp/**"]
deny_write = ["/etc/**", "**/.bashrc"]

[network]
allow_hosts = ["docs.python.org"]
methods = ["GET", "HEAD", "POST"]

[limits]
max_arg_bytes = 65536
max_calls_per_session = 200

[scripts]
require_trusted = true
trusted_dirs = ["./scripts/**", "./bin/**"]
```

匹配优先级：精确工具名 → `match` 通配。未登记工具由 `guards.contract.unknown_tool` 决定。

### 技能合约（自动生成）

`contracts/skills/<skill>.toml`：

```toml
[tool]
name = "*"
kind = "skill"

[skill]
name = "note-taker"
status = "quarantined"     # trusted | conditional | quarantined
capabilities = ["fs_read", "fs_write"]
declared = ["fs_read", "fs_write"]
observed = ["fs_read", "fs_write", "network", "shell"]
```

运行时：调用带 `meta["skill"]` 时按 `status` 收紧；`conditional` 下越界能力转人工，
`quarantined` 直接拒绝。

## 8. 校验与排错

```bash
agentjudge doctor                  # 路径、密钥、合约、数据集自检
agentjudge rules test "..."        # 单条文本试跑
agentjudge audit verify            # 审计链完整性
```

策略错误会抛 `PolicyError`（字段非法、正则非法、规则 ID 重复、继承循环、阈值倒置等），
启动即失败，不会带病运行。
