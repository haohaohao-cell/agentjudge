# 部署与运维

## 1. 本地 / 内网裸机

要求：Python 3.11+，无需第三方包。

```bash
python -m venv .venv
. .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -e .
agentjudge doctor
agentjudge serve --host 127.0.0.1 --port 8737
```

离线环境：把仓库（或 `pip download` 好的 wheel）拷入内网，`pip install --no-index` 或直接
`PYTHONPATH=src python -m agentjudge serve`。

## 2. Docker

```bash
export AGENTJUDGE_TOKEN=$(python -c "import secrets;print(secrets.token_urlsafe(32))")
docker build -f deploy/Dockerfile -t agentjudge:0.1.0 .
docker run -d --name agentjudge \
  -p 127.0.0.1:8737:8737 \
  -e AGENTJUDGE_TOKEN \
  -v agentjudge-data:/app/var \
  agentjudge:0.1.0
```

或 `docker compose -f deploy/docker-compose.yml up -d`。

容器特性：非 root 用户、`read_only` 根文件系统、`no-new-privileges`、仅 `var/` 可写、
内置 healthcheck、强制 Token。

## 3. systemd

```bash
sudo useradd --system --create-home --shell /usr/sbin/nologin agentjudge
sudo mkdir -p /opt/agentjudge /etc/agentjudge
sudo rsync -a --exclude var ./ /opt/agentjudge/
sudo -u agentjudge python -m venv /opt/agentjudge/.venv
sudo -u agentjudge /opt/agentjudge/.venv/bin/pip install /opt/agentjudge
sudo install -m 600 -o root -g agentjudge deploy/env.example /etc/agentjudge/env
sudo cp deploy/agentjudge.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now agentjudge
```

`deploy/agentjudge.service` 已启用 `ProtectSystem=strict`、`PrivateTmp`、
`RestrictSUIDSGID`，仅 `var/` 可写。

## 4. 密钥与数据

| 数据 | 位置 | 要求 |
| --- | --- | --- |
| HMAC 密钥 | `AGENTJUDGE_HMAC_KEY` 或 `var/hmac.key` | 32 字节随机；文件 0600；进 KMS 更好 |
| 独立尾锚 | `var/tail.anchor` | 最好放到另一块盘/对象存储 |
| 审计库 | `var/agentjudge.db` | 只允许服务账号写；定期备份 |
| 访问 Token | `AGENTJUDGE_TOKEN` | 32 字节以上随机；轮换周期化 |

首次启动会生成 `var/hmac.key`。**密钥丢失 = 历史链无法校验**，务必与数据库一起备份。
密钥轮换流程见 [audit-chain.md](audit-chain.md#7-密钥轮换)。

## 5. 反向代理

工作台没有内置 TLS，生产建议放在 Nginx/Caddy 之后：

```nginx
server {
    listen 443 ssl;
    server_name judge.internal;

    location / {
        proxy_pass http://127.0.0.1:8737;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_buffering off;          # SSE 必须关闭缓冲
        proxy_read_timeout 3600s;
    }
}
```

同时把 `agentjudge serve --host 127.0.0.1` 保持为仅本机监听，只暴露代理端口。

## 6. 灰度上线

1. 用 `policies/monitor.toml`（`mode = "monitor"`）跑一周：只记录「本应拦截」的动作；
2. 看工作台/`metrics` 的 `would_block` 分布，调整规则与白名单；
3. 切 `enforce`，先只对高风险工具（shell、网络）启用，再逐步覆盖全部工具；
4. 保留 `ESCALATE` 的人工复核通道，避免硬性阻断业务。

## 7. 容量与性能

- 单进程即可支撑每秒数百次裁决（确定性路径 ~0.5ms）；
- 每条裁决写 1~2 条审计记录，SQLite `synchronous=FULL`，吞吐瓶颈通常在磁盘 fsync；
- 会话表在内存，`Judge.hydrate()` 默认回放最近 1000 条裁决，可用 `AGENTJUDGE_HYDRATE` 调整；
- 大规模部署建议每个租户/业务线独立实例 + 独立审计库，便于隔离与归档。

## 8. 备份与归档

```bash
# 每日导出取证包（含校验结论），异地保存
agentjudge audit export --out /backup/agentjudge-$(date +%F).zip
# 备份库与密钥（密钥单独加密保存）
cp var/agentjudge.db /backup/agentjudge-$(date +%F).db
```

恢复后先 `agentjudge audit verify --db ... --anchor ...`，再启动服务。

## 9. 升级

1. `git pull` 或换新 wheel；
2. `agentjudge doctor` 检查策略/合约兼容性（策略 schema 有版本校验）；
3. `python -m unittest discover -s tests` + `agentjudge eval` 做回归；
4. `systemctl restart agentjudge`；审计库与密钥无需迁移（schema 只增不改）。

## 10. 监控告警

建议接入的外部告警：

- `GET /api/v1/audit/verify` 返回 `ok=false`（最高优先级）；
- `metrics.by_action.deny / total` 突增；
- `metrics.latency_ms.p95` 持续 > 50ms；
- `store.records` 增长异常（可能被刷）；
- `reviews/pending` 积压（人工复核跟不上）。
