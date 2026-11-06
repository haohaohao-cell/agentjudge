# 变更日志

格式参考 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

## [未发布]

### 新增

- **告警**：飞书 / 企业微信 / 钉钉 / Slack / 通用 Webhook + SMTP 邮件；
  独立线程 + 有界队列 + 令牌桶限流，失败不影响裁决（`src/agentjudge/alerting.py`）。
- **统一事件台账**：工作台跨会话检索审计记录（按类型/会话过滤，点击跳到时间线）。
- **台账导出**：`audit export --format csv|html`，工作台台账内也可一键导出；
  CSV 带 UTF-8 BOM 便于 Excel，HTML 为自包含报告且对所有字段做转义。
- **策略回归守护**：`datasets/baseline.json` 固化基线，
  `eval --check` 在 ASR 上升、场景退化、新增误报或 FPR 超容差时返回退出码 1；
  CI 每次评测都过这道门禁。
- **MCP Server**：`agentjudge mcp` 在 stdio 上跑标准 MCP JSON-RPC，暴露
  `intercept_tool_call` / `observe_tool_result` / `verify_audit` / `inspect_skill` /
  `get_policy` 五个工具，Claude Desktop、Cursor 可直接接入；
  `inspect_skill` 限制在 `--skill-root` 内，stdout 只输出协议消息。
- **MCP 客户端 e2e 示例**：`examples/mcp_client.py` 连真实 MCP Server 子进程，
  走完「放行 → 回传 → 拦截 → 隔离 → 污染会话收紧 → 链校验」，带 CI 回归测试。
- **`agentjudge alert test`**：告警通道自检，退出码区分「全部成功 / 有失败 / 未配置」。
- **测试**：告警 22 个、LLM 真实 HTTP 路径 8 个、CLI 端到端 10 个、
  导出 13 个、回归守护 17 个、MCP 21 个、MCP e2e 1 个，测试总数 98 → 195。

### 变更

- CLI `--json` 输出统一为 `{allow, action, reason, decision}` 信封，与 HTTP API 对齐。
- `agentjudge skill inspect --json` 在非 trusted 时返回退出码 2（此前恒为 0）。
- 修正文档中「重启后污点上下文完整恢复」的表述：审计只存脱敏预览，
  跨重启的数据流判定为尽力恢复。

## [0.1.0] - 2026-11-02

### 新增

- **裁决引擎**：五道确定性守卫流水线（蜜标、隐写、合约、规则、数据流），
  三态裁决（allow/deny/escalate），失败即拒绝，监控模式。
- **会话级数据流**：敏感数据打标（凭据、密钥、PII、注入指令），
  污点传播支持精确匹配、base64/hex/URL 编码变体与词元重叠。
- **结果侧复核**：读取到注入指令即隔离（读取即隔离），污染会话后续动作收紧。
- **防篡改审计链**：HMAC-SHA256 链 + 数据库外独立尾锚 + 尾状态双位置校验，
  支持校验、封存、取证包导出、重启回放。
- **技能言行体检**：Python AST + Shell 正则抽取实测行为，与文档声明逐维对照，
  生成 trust 评级与可机读技能合约。
- **语义研判**：只读调查循环（最多 8 轮，硬上限 32），OpenAI 兼容客户端，
  离线启发式回退，轮次不足/异常一律收紧。
- **接入层**：Python SDK（装饰器/动态分发）、HTTP API、MCP 代理、OpenClaw pointer 插件。
- **工作台**：会话时间线、数据流边、规则证据、人工复核队列、审计链校验、
  技能体检、SSE 实时事件。
- **评测体系**：17 个多轮红队场景、55 条良性语料、指标报告（ASR/FPR/延迟分位）。
- **工程化**：98 个测试、CI（3 个 Python 版本 × 2 个平台）、Docker/systemd 部署、
  完整文档（架构、威胁模型、策略手册、审计链、API、部署、评测、路线图）。

### 基线指标

- 红队场景拦截 15/15，ASR 0.0%
- 良性任务完成率 96.4%，FPR 3.6%
- 裁决延迟 p50 0.48ms / p95 0.80ms

### 已知问题

- `rm -rf`、`sudo` 等保守规则会带来可用性代价，需要按业务灰度调整；
- 污点传播对重度语义改写仍有漏判；
- 密钥轮换尚未提供 CLI 参数。
