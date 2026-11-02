# 告警

告警是旁路：它**不参与裁决**，不阻断主流程，发送失败只记日志。目标是让安全团队
在拦截发生的几秒内收到通知，而不是每天翻工作台。

## 1. 支持通道

| 类型 | 报文 | 说明 |
| --- | --- | --- |
| `feishu` | `{"msg_type":"text","content":{"text":...}}` | 飞书自定义机器人 |
| `wecom` | `{"msgtype":"text","text":{"content":...}}` | 企业微信机器人 |
| `dingtalk` | 同上 | 钉钉机器人 |
| `slack` | `{"text":...}` | Slack Incoming Webhook |
| `generic` | `{"event": {...}}` | 任意接收端，字段见下 |
| `email` | SMTP 纯文本邮件 | 支持 SSL / STARTTLS |

`generic` 的事件字段：`kind`、`title`、`detail`、`severity`、`session_id`、`tool`、
`risk`、`decision_id`、`ts`。

## 2. 配置

```toml
[alerting]
enabled = true
min_severity = "high"        # 只告警 high / critical
on_deny = true
on_escalate = true
on_quarantine = true
rate_limit_per_min = 30
timeout_s = 5.0
console = false

[[alerting.webhooks]]
type = "feishu"
url_env = "AGENTJUDGE_FEISHU_WEBHOOK"

[[alerting.webhooks]]
type = "generic"
url = "https://siem.internal/hooks/agentjudge"

[alerting.email]
enabled = true
host = "smtp.internal"
port = 587
starttls = true
username = "judge@example.com"
password_env = "AGENTJUDGE_SMTP_PASSWORD"
sender = "judge@example.com"
recipients = ["sec@example.com", "oncall@example.com"]
```

- 优先用 `url_env` / `password_env`，别把 Webhook 与口令写进仓库；
- 未配置地址的通道会被跳过并打 warning，不会导致启动失败；
- `console = true` 同时打印到 stdout，便于本地调试。

## 3. 触发条件

| 条件 | 事件 `kind` |
| --- | --- |
| 裁决为 `deny` 且最高严重度 ≥ `min_severity` | `deny` |
| 裁决为 `escalate` 且最高严重度 ≥ `min_severity` | `escalate` |
| 工具返回值被隔离（读取即隔离） | `quarantine` |

监控模式（`mode = "monitor"`）下裁决仍是 `deny`，因此**照样会告警**——这正是灰度期
需要的：先看见，再决定是否真的拦。

## 4. 可靠性与限流

- 有界队列（256 条）+ 独立守护线程，`intercept()` 不等待网络；
- 令牌桶限流，默认 30 条/分钟；超出直接丢弃并计入 `metrics.alerting.dropped`；
- 队列满同样丢弃，不阻塞裁决；
- 单通道异常被捕获，不影响其他通道，也不会冒泡到裁决路径；
- 进程退出时 `Judge.close()` 会等待在途告警（最多 2 秒）。

## 5. 自检

```bash
python run.py alert test --severity critical
# 告警通道  2 个
#   - {'name': 'webhook:feishu', 'configured': True, 'type': 'feishu'}
#   - {'name': 'email', 'configured': True, 'recipients': 2}
# 发送结果：成功  成功 2 / 失败 0 / 丢弃 0
```

退出码：`0` 全部成功；`1` 有通道失败；`2` 未配置任何通道。

## 6. 观测

`GET /api/v1/metrics` 的 `alerting` 字段：

```json
{
  "enabled": true,
  "channels": [{"name": "webhook:feishu", "configured": true, "type": "feishu"}],
  "sent": 12, "failed": 0, "dropped": 3, "errors": 0
}
```

工作台「运行指标」面板在启用告警后会多出一张「告警投递」卡片。

## 7. 与审计的关系

告警是**通知**，审计链是**证据**。告警丢失不影响取证；审计链断裂则告警也失去意义。
因此生产环境建议：

- 接收端做去重与聚合（同会话同规则 5 分钟内只提醒一次）；
- 把 `audit verify` 失败单独配置为最高优先级告警（当前需外部定时任务调用
  `/api/v1/audit/verify` 并检查 `ok` 字段）；
- 告警内容已脱敏，不要在模板里再回填原始参数。
