# 安全策略

## 报告漏洞

请**不要**通过公开 issue 披露安全问题。使用 GitHub 私密安全公告：

> https://github.com/haohaohao-cell/agentjudge/security/advisories/new

或邮件联系维护者（在仓库 About 中）。请在报告中包含：影响版本、复现步骤、
影响面（能否绕过裁决 / 篡改审计 / 窃取密钥）、你的联系方式。

我们会在 7 天内确认，30 天内给出修复或缓解方案；修复发布后再公开细节。

## 支持版本

| 版本 | 支持 |
| --- | --- |
| 0.1.x | ✅ |

## 威胁模型摘要

完整内容见 [docs/threat-model.md](docs/threat-model.md)。要点：

- 本系统约束**智能体的外显动作**，不修改模型本身；
- 模型输出、工具返回值、外部文档、技能代码均视为不可信；
- 语义研判只能收紧，不能放开；
- 审计链的信任根是 HMAC 密钥 + 库外独立尾锚。

## 部署安全清单

- [ ] 监听非本机地址时设置了强随机 `AGENTJUDGE_TOKEN`
- [ ] `AGENTJUDGE_HMAC_KEY` 由 KMS/环境变量注入，或 `var/hmac.key` 为 0600
- [ ] 尾锚存放在数据库之外（独立磁盘/对象存储/只读介质）
- [ ] 审计库目录仅服务账号可写
- [ ] 反向代理启用 TLS，且 `proxy_buffering off`（SSE）
- [ ] 定期 `agentjudge audit verify` 并接入告警
- [ ] 定期 `agentjudge audit export` 异地留存
- [ ] 容器以非 root、只读根文件系统运行
- [ ] 未开启 `watcher.can_release`，或已评估模型可信度
- [ ] 策略与合约文件纳入 code review

## 已知限制（安全相关）

- 污点传播基于内容比对，重度语义改写可能绕过；
- 静态体检不执行技能代码，混淆样本可能漏检；
- 攻击者同时获取密钥、审计库与尾锚写入权限时可重写历史；
- 本系统不防护内核级逃逸与侧信道。
