"""告警通知：飞书 / 企业微信 / 钉钉 / Slack / 通用 Webhook + SMTP 邮件。

设计约束：

* **绝不阻断裁决**：告警走独立线程与有界队列，发送失败只记日志；
* **限流**：默认每分钟 30 条，避免被批量攻击刷爆接收端；
* **密钥不出仓库**：Webhook 地址与 SMTP 口令都支持 ``*_env`` 从环境变量读取；
* **可测**：传输层可替换，测试用本地 mock HTTP 服务即可覆盖。

配置示例（TOML）::

    [alerting]
    enabled = true
    min_severity = "high"          # 只告警 high / critical
    rate_limit_per_min = 30
    timeout_s = 5

    [[alerting.webhooks]]
    type = "feishu"                # feishu | wecom | dingtalk | slack | generic
    url_env = "AGENTJUDGE_FEISHU_WEBHOOK"

    [alerting.email]
    enabled = false
    host = "smtp.example.com"
    port = 587
    starttls = true
    username = "judge@example.com"
    password_env = "AGENTJUDGE_SMTP_PASSWORD"
    sender = "judge@example.com"
    recipients = ["sec@example.com"]
"""

from __future__ import annotations

import json
import logging
import os
import queue
import smtplib
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from email.message import EmailMessage
from typing import Any

from .types import Action, Decision, Severity
from .utils import mask_secrets, truncate, utc_now_iso

log = logging.getLogger("agentjudge.alerting")

MAX_QUEUE = 256


@dataclass(slots=True)
class AlertConfig:
    enabled: bool = False
    min_severity: str = "high"
    on_deny: bool = True
    on_escalate: bool = True
    on_quarantine: bool = True
    rate_limit_per_min: int = 30
    timeout_s: float = 5.0
    console: bool = False
    webhooks: list[dict[str, Any]] = field(default_factory=list)
    email: dict[str, Any] = field(default_factory=dict)

    @property
    def min_rank(self) -> int:
        try:
            return Severity(self.min_severity).rank
        except ValueError:
            return Severity.HIGH.rank

    def to_dict(self) -> dict[str, Any]:
        """对外快照：隐藏 URL/口令等敏感字段。"""
        return {
            "enabled": self.enabled,
            "min_severity": self.min_severity,
            "rate_limit_per_min": self.rate_limit_per_min,
            "webhooks": [
                {"type": w.get("type", "generic"), "configured": bool(w.get("url") or w.get("url_env"))}
                for w in self.webhooks
            ],
            "email": {
                "enabled": bool(self.email.get("enabled")),
                "host": self.email.get("host", ""),
                "recipients": len(self.email.get("recipients", []) or []),
            },
            "console": self.console,
        }


@dataclass(slots=True)
class AlertEvent:
    kind: str  # deny | escalate | quarantine | chain_broken | test
    title: str
    detail: str
    severity: str = "high"
    session_id: str = ""
    tool: str = ""
    risk: int = 0
    decision_id: str = ""
    ts: str = field(default_factory=utc_now_iso)

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "title": self.title,
            "detail": self.detail,
            "severity": self.severity,
            "session_id": self.session_id,
            "tool": self.tool,
            "risk": self.risk,
            "decision_id": self.decision_id,
            "ts": self.ts,
        }

    def text(self) -> str:
        return "\n".join(
            [
                f"[AgentJudge] {self.title}",
                f"动作: {self.kind}   严重度: {self.severity}   风险: {self.risk}/100",
                f"工具: {self.tool}   会话: {self.session_id}   步骤: {self.decision_id}",
                f"详情: {self.detail}",
                f"时间: {self.ts}",
            ]
        )


# ---------------------------------------------------------------------------
# 通知通道
# ---------------------------------------------------------------------------
class Notifier:
    name = "notifier"

    def send(self, event: AlertEvent) -> bool:
        raise NotImplementedError

    def describe(self) -> dict[str, Any]:
        return {"name": self.name, "configured": True}


class WebhookNotifier(Notifier):
    """通用 Webhook；按机器人类型生成对应报文。"""

    TEMPLATES = {"feishu", "wecom", "dingtalk", "slack", "generic"}

    def __init__(self, url: str, kind: str = "generic", *, timeout_s: float = 5.0, name: str = ""):
        if kind not in self.TEMPLATES:
            raise ValueError(f"不支持的 webhook 类型: {kind}")
        self.url = url
        self.kind = kind
        self.timeout_s = timeout_s
        self.name = name or f"webhook:{kind}"

    def _payload(self, event: AlertEvent) -> dict[str, Any]:
        text = event.text()
        if self.kind == "feishu":
            return {"msg_type": "text", "content": {"text": text}}
        if self.kind == "wecom":
            return {"msgtype": "text", "text": {"content": text}}
        if self.kind == "dingtalk":
            return {"msgtype": "text", "text": {"content": text}}
        if self.kind == "slack":
            return {"text": text}
        return {"event": event.to_dict()}

    def send(self, event: AlertEvent) -> bool:
        data = json.dumps(self._payload(event), ensure_ascii=False).encode("utf-8")
        request = urllib.request.Request(
            self.url,
            data=data,
            headers={"Content-Type": "application/json; charset=utf-8"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout_s) as response:
                response.read(1024)
            return True
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            log.warning("webhook 告警失败 %s: %s", self.kind, exc)
            return False

    def describe(self) -> dict[str, Any]:
        return {"name": self.name, "configured": True, "type": self.kind}


class EmailNotifier(Notifier):
    """SMTP 邮件告警（支持 SSL / STARTTLS）。"""

    name = "email"

    def __init__(
        self,
        *,
        host: str,
        port: int = 587,
        starttls: bool = True,
        ssl: bool = False,
        username: str = "",
        password: str = "",
        sender: str = "",
        recipients: list[str] | None = None,
        timeout_s: float = 5.0,
    ):
        self.host = host
        self.port = int(port)
        self.starttls = bool(starttls)
        self.ssl = bool(ssl)
        self.username = username
        self.password = password
        self.sender = sender or username
        self.recipients = list(recipients or [])
        self.timeout_s = timeout_s
        if not self.recipients:
            raise ValueError("email.recipients 不能为空")

    def send(self, event: AlertEvent) -> bool:
        message = EmailMessage()
        message["Subject"] = f"[AgentJudge] {event.title}"
        message["From"] = self.sender
        message["To"] = ", ".join(self.recipients)
        message["X-AgentJudge-Severity"] = event.severity
        message.set_content(event.text())
        try:
            if self.ssl:
                server: smtplib.SMTP = smtplib.SMTP_SSL(self.host, self.port, timeout=self.timeout_s)
            else:
                server = smtplib.SMTP(self.host, self.port, timeout=self.timeout_s)
            with server:
                if self.starttls and not self.ssl:
                    server.starttls()
                if self.username:
                    server.login(self.username, self.password)
                server.send_message(message)
            return True
        except (smtplib.SMTPException, OSError) as exc:
            log.warning("邮件告警失败: %s", exc)
            return False

    def describe(self) -> dict[str, Any]:
        return {"name": self.name, "configured": True, "recipients": len(self.recipients)}


class ConsoleNotifier(Notifier):
    """调试用：打印到标准输出，不长连接、不发网络请求。"""

    name = "console"

    def __init__(self) -> None:
        self.sent: list[AlertEvent] = []

    def send(self, event: AlertEvent) -> bool:
        self.sent.append(event)
        print(f"[alert] {event.kind.upper()} {event.tool} risk={event.risk} {truncate(event.title, 80)}")
        return True


class MemoryNotifier(Notifier):
    """测试用：记录事件，不做 IO。"""

    name = "memory"

    def __init__(self) -> None:
        self.events: list[AlertEvent] = []
        self.ok = True

    def send(self, event: AlertEvent) -> bool:
        self.events.append(event)
        return self.ok


# ---------------------------------------------------------------------------
# 管理器
# ---------------------------------------------------------------------------
class AlertManager:
    """有界队列 + 后台线程 + 令牌桶限流。"""

    def __init__(self, config: AlertConfig, notifiers: list[Notifier] | None = None):
        self.config = config
        self.notifiers = list(notifiers or [])
        self._queue: queue.Queue[AlertEvent | None] = queue.Queue(maxsize=MAX_QUEUE)
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._tokens = float(max(1, config.rate_limit_per_min))
        self._last_refill = time.monotonic()
        self.dropped = 0
        self.sent = 0
        self.failed = 0
        self.inflight = 0

    # -- 生命周期 ---------------------------------------------------------
    def start(self) -> None:
        if self._thread is not None or not self.notifiers:
            return
        self._thread = threading.Thread(target=self._run, name="agentjudge-alerts", daemon=True)
        self._thread.start()

    def close(self, timeout: float = 2.0) -> None:
        self._stop.set()
        try:
            self._queue.put_nowait(None)
        except queue.Full:
            pass
        if self._thread is not None:
            self._thread.join(timeout=timeout)
            self._thread = None

    # -- 提交 -------------------------------------------------------------
    def should_alert(self, decision: Decision) -> bool:
        cfg = self.config
        if not cfg.enabled or not self.notifiers:
            return False
        if decision.quarantined and cfg.on_quarantine:
            return True
        if decision.action is Action.DENY and cfg.on_deny:
            return self._severe_enough(decision)
        if decision.action is Action.ESCALATE and cfg.on_escalate:
            return self._severe_enough(decision)
        return False

    def _severe_enough(self, decision: Decision) -> bool:
        top = max((f.severity.rank for f in decision.findings), default=Severity.LOW.rank)
        return top >= self.config.min_rank

    def submit(self, decision: Decision) -> bool:
        if not self.should_alert(decision):
            return False
        event = decision_to_event(decision)
        return self.enqueue(event)

    def enqueue(self, event: AlertEvent) -> bool:
        if not self._allow():
            self.dropped += 1
            log.debug("告警被限流丢弃: %s", event.title)
            return False
        try:
            self._queue.put_nowait(event)
        except queue.Full:
            self.dropped += 1
            return False
        self.start()
        return True

    def flush(self, timeout: float = 3.0) -> bool:
        """等待队列清空且发送完成（测试与 CLI 使用）。"""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self._queue.empty() and self.inflight == 0:
                return True
            time.sleep(0.02)
        return False

    # -- 限流 -------------------------------------------------------------
    def _allow(self) -> bool:
        rate = max(1, self.config.rate_limit_per_min)
        with self._lock:
            now = time.monotonic()
            self._tokens = min(float(rate), self._tokens + (now - self._last_refill) * (rate / 60.0))
            self._last_refill = now
            if self._tokens < 1.0:
                return False
            self._tokens -= 1.0
            return True

    # -- 工作线程 ---------------------------------------------------------
    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                event = self._queue.get(timeout=0.2)
            except queue.Empty:
                continue
            if event is None:
                break
            self.inflight += 1
            try:
                for notifier in self.notifiers:
                    try:
                        ok = notifier.send(event)
                    except Exception as exc:  # noqa: BLE001 - 告警永不抛出
                        log.warning("告警通道 %s 异常: %s", notifier.name, exc)
                        ok = False
                    if ok:
                        self.sent += 1
                    else:
                        self.failed += 1
            finally:
                self.inflight -= 1

    def describe(self) -> list[dict[str, Any]]:
        return [n.describe() for n in self.notifiers]


def decision_to_event(decision: Decision) -> AlertEvent:
    """把裁决转成告警事件（脱敏）。"""
    if decision.quarantined:
        kind = "quarantine"
        title = "工具返回值被隔离"
    elif decision.action is Action.DENY:
        kind = "deny"
        title = "危险工具调用被拦截"
    else:
        kind = "escalate"
        title = "工具调用待人工复核"
    reasons = [f"{r['rule_id']} {r['title']}" for r in decision.reasons[:3]]
    if not reasons:
        reasons = [f"{f.rule_id} {f.title}" for f in decision.findings[:3]]
    detail = "；".join(reasons) or decision.explanation
    return AlertEvent(
        kind=kind,
        title=title,
        detail=mask_secrets(truncate(detail, 300)),
        severity=max((f.severity.value for f in decision.findings), key=lambda s: Severity(s).rank, default="low"),
        session_id=decision.session_id,
        tool=decision.tool,
        risk=decision.risk,
        decision_id=decision.decision_id,
    )


def build_alerting(config: AlertConfig) -> AlertManager:
    """根据配置构造通知器。缺环境变量的通道会被跳过并记录。"""
    notifiers: list[Notifier] = []
    if config.console:
        notifiers.append(ConsoleNotifier())
    for item in config.webhooks:
        kind = str(item.get("type", "generic"))
        url = str(item.get("url") or "")
        if not url and item.get("url_env"):
            url = os.environ.get(str(item["url_env"]), "").strip()
        if not url:
            log.warning("webhook(%s) 未配置地址，已跳过", kind)
            continue
        try:
            notifiers.append(WebhookNotifier(url, kind, timeout_s=config.timeout_s))
        except ValueError as exc:
            log.warning("webhook 配置非法: %s", exc)
    email_cfg = config.email or {}
    if email_cfg.get("enabled"):
        password = os.environ.get(str(email_cfg.get("password_env", "")), "")
        try:
            notifiers.append(
                EmailNotifier(
                    host=str(email_cfg.get("host", "")),
                    port=int(email_cfg.get("port", 587)),
                    starttls=bool(email_cfg.get("starttls", True)),
                    ssl=bool(email_cfg.get("ssl", False)),
                    username=str(email_cfg.get("username", "")),
                    password=password,
                    sender=str(email_cfg.get("sender", "")),
                    recipients=[str(x) for x in email_cfg.get("recipients", [])],
                    timeout_s=config.timeout_s,
                )
            )
        except (ValueError, TypeError) as exc:
            log.warning("邮件告警配置非法: %s", exc)
    return AlertManager(config, notifiers)


__all__ = [
    "AlertConfig",
    "AlertEvent",
    "AlertManager",
    "ConsoleNotifier",
    "EmailNotifier",
    "MemoryNotifier",
    "Notifier",
    "WebhookNotifier",
    "build_alerting",
    "decision_to_event",
]
