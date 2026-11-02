"""审计记录导出：CSV 与自包含 HTML。

导出只读审计库，不修改任何数据；HTML 会内联样式，单文件可直接发给人看。
所有字段都做 HTML 转义——审计内容来自被监督方，不能当成可信 HTML。
"""

from __future__ import annotations

import csv
import html
import io
import json
from pathlib import Path
from typing import Any, Iterable

from ..utils import utc_now_iso
from .chain import ChainRecord, VerifyResult

CSV_HEADER = [
    "序号",
    "时间",
    "类型",
    "动作",
    "工具",
    "会话",
    "风险",
    "摘要",
    "决策号",
    "当前指纹",
    "前序指纹",
]

_KIND_LABELS = {
    "decision": "裁决",
    "result": "返回值",
    "flow_edge": "数据流边",
    "revise": "隔离",
    "review": "人工复核",
}


def record_summary(record: ChainRecord) -> str:
    """一行摘要，与工作台台账口径一致。"""
    payload = record.payload or {}
    kind = record.kind
    if kind == "decision":
        decision = payload.get("decision") or {}
        reasons = "；".join(
            f"{r.get('rule_id')} {r.get('title')}" for r in (decision.get("reasons") or [])[:3]
        )
        return reasons or str(decision.get("explanation") or "")
    if kind == "result":
        labels = ",".join(str(x) for x in (payload.get("labels") or []))
        base = f"返回值 {payload.get('chars', 0)} 字符"
        return f"{base} · {labels}" if labels else base
    if kind == "flow_edge":
        edges = payload.get("edges") or []
        parts = []
        for edge in edges:
            labels = ",".join(str(x) for x in (edge.get("labels") or []))
            parts.append(f"#{edge.get('source_step')}->{edge.get('source_tool')}({labels})")
        return "数据流边: " + "; ".join(parts)
    if kind == "revise":
        return f"读取即隔离：{payload.get('reason', '')}"
    if kind == "review":
        return f"{payload.get('review_status', '')} by {payload.get('reviewer', '')}".strip()
    return json.dumps(payload, ensure_ascii=False)[:160]


def record_risk(record: ChainRecord) -> int:
    decision = (record.payload or {}).get("decision") or {}
    try:
        return int(decision.get("risk") or 0)
    except (TypeError, ValueError):
        return 0


def record_decision_id(record: ChainRecord) -> str:
    payload = record.payload or {}
    if record.kind == "decision":
        return str((payload.get("decision") or {}).get("decision_id") or "")
    return str(payload.get("decision_id") or "")


def records_to_csv(records: Iterable[ChainRecord], *, include_payload: bool = False) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    header = list(CSV_HEADER)
    if include_payload:
        header.append("载荷")
    writer.writerow(header)
    for record in records:
        row = [
            record.seq,
            record.ts,
            _KIND_LABELS.get(record.kind, record.kind),
            record.action or "",
            record.tool or "",
            record.session_id or "",
            record_risk(record) or "",
            record_summary(record),
            record_decision_id(record),
            record.current,
            record.prev,
        ]
        if include_payload:
            row.append(json.dumps(record.payload, ensure_ascii=False)[:6000])
        writer.writerow(row)
    return buffer.getvalue()


def write_csv(path: str | Path, records: Iterable[ChainRecord], *, include_payload: bool = False) -> Path:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    # utf-8-sig：Excel 双击打开不乱码
    target.write_text(records_to_csv(records, include_payload=include_payload), encoding="utf-8-sig")
    return target


def _badge(action: str) -> str:
    if action == "deny":
        return '<span class="badge deny">DENY</span>'
    if action == "escalate":
        return '<span class="badge escalate">ESCALATE</span>'
    if action == "allow":
        return '<span class="badge allow">ALLOW</span>'
    return '<span class="badge none">—</span>'


def records_to_html(
    records: Iterable[ChainRecord],
    *,
    verification: VerifyResult | None = None,
    policy_version: str = "",
    title: str = "AgentJudge 审计台账",
    max_payload_chars: int = 4000,
) -> str:
    rows = list(records)
    counts = {"deny": 0, "escalate": 0, "allow": 0}
    for record in rows:
        if record.action in counts:
            counts[record.action] += 1
    chain_ok = verification.ok if verification else None
    chain_class = "ok" if chain_ok else "bad"
    chain_text = "链完整" if chain_ok else "链断裂" if chain_ok is False else "未校验"
    anchor = (
        "已封存"
        if verification and verification.anchor_present
        else "未封存"
        if verification
        else "—"
    )
    chain_detail = ""
    if verification and not verification.ok:
        chain_detail = (
            f'<div class="chain-detail">断裂点 #{html.escape(str(verification.broken_at))}'
            f' · {html.escape(verification.reason)} · {html.escape(verification.detail)}</div>'
        )

    body_rows = []
    for record in rows:
        summary = record_summary(record)
        payload = json.dumps(record.payload, ensure_ascii=False)[:max_payload_chars]
        body_rows.append(
            "<tr>"
            f'<td class="seq">{record.seq}</td>'
            f'<td class="time">{html.escape(record.ts)}</td>'
            f'<td class="kind">{html.escape(_KIND_LABELS.get(record.kind, record.kind))}</td>'
            f"<td>{_badge(record.action or '')}</td>"
            f'<td class="mono">{html.escape(record.tool or "—")}</td>'
            f'<td class="mono session">{html.escape(record.session_id or "—")}</td>'
            f'<td class="risk">{record_risk(record) or "—"}</td>'
            f"<td>{html.escape(summary)}</td>"
            f"<td><details><summary>载荷</summary><pre>{html.escape(payload)}</pre></details></td>"
            "</tr>"
        )

    generated = utc_now_iso()
    return f"""<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{html.escape(title)}</title>
<style>
  :root {{ --bg:#0a0e13; --panel:#111823; --border:#1e2a3a; --text:#e6edf6;
          --muted:#8b9bb0; --allow:#35d07f; --deny:#ff4d5e; --warn:#f5b544; }}
  * {{ box-sizing:border-box; }}
  body {{ margin:0; padding:28px; background:var(--bg); color:var(--text);
          font-family:"PingFang SC","Microsoft YaHei",system-ui,sans-serif; font-size:13px; }}
  h1 {{ font-size:19px; margin:0 0 4px; }}
  .sub {{ color:var(--muted); font-size:12px; margin-bottom:18px; }}
  .cards {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr));
            gap:10px; margin-bottom:18px; }}
  .card {{ background:var(--panel); border:1px solid var(--border); border-radius:9px; padding:10px 12px; }}
  .card .k {{ color:var(--muted); font-size:11px; }}
  .card .v {{ font-size:18px; font-family:ui-monospace,Consolas,monospace; margin-top:4px; }}
  .v.ok {{ color:var(--allow); }} .v.bad {{ color:var(--deny); }}
  .chain-detail {{ color:var(--deny); font-size:12px; margin:-6px 0 14px; }}
  table {{ width:100%; border-collapse:collapse; background:var(--panel);
           border:1px solid var(--border); border-radius:9px; overflow:hidden; }}
  th {{ background:#16202c; color:var(--muted); font-weight:500; font-size:11px;
        text-align:left; padding:8px 10px; }}
  td {{ padding:7px 10px; border-top:1px solid #182231; vertical-align:top; }}
  td.seq {{ font-family:ui-monospace,Consolas,monospace; color:var(--muted); }}
  td.time, td.mono {{ font-family:ui-monospace,Consolas,monospace; font-size:11.5px; }}
  td.session {{ color:var(--muted); max-width:210px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }}
  td.risk {{ font-family:ui-monospace,Consolas,monospace; }}
  .badge {{ font-family:ui-monospace,Consolas,monospace; font-size:10px; font-weight:700;
            padding:2px 6px; border-radius:4px; }}
  .badge.allow {{ color:var(--allow); background:rgba(53,208,127,.14); }}
  .badge.deny {{ color:var(--deny); background:rgba(255,77,94,.14); }}
  .badge.escalate {{ color:var(--warn); background:rgba(245,181,68,.14); }}
  .badge.none {{ color:var(--muted); }}
  details summary {{ cursor:pointer; color:var(--muted); font-size:11px; }}
  pre {{ white-space:pre-wrap; word-break:break-all; background:#0a1017; border:1px solid #182231;
         border-radius:6px; padding:8px; font-size:11px; max-height:260px; overflow:auto; }}
  footer {{ margin-top:16px; color:var(--muted); font-size:11px; line-height:1.8; }}
</style>
</head>
<body>
  <h1>{html.escape(title)}</h1>
  <div class="sub">导出时间 {html.escape(generated)} · 策略 {html.escape(policy_version or "unknown")}
    · 共 {len(rows)} 条记录</div>

  <div class="cards">
    <div class="card"><div class="k">链校验</div><div class="v {chain_class}">{chain_text}</div></div>
    <div class="card"><div class="k">独立尾锚</div><div class="v">{anchor}</div></div>
    <div class="card"><div class="k">拒绝</div><div class="v">{counts["deny"]}</div></div>
    <div class="card"><div class="k">转人工</div><div class="v">{counts["escalate"]}</div></div>
    <div class="card"><div class="k">放行</div><div class="v">{counts["allow"]}</div></div>
  </div>
  {chain_detail}

  <table>
    <thead><tr>
      <th>#</th><th>时间</th><th>类型</th><th>动作</th><th>工具</th><th>会话</th>
      <th>风险</th><th>摘要</th><th>载荷</th>
    </tr></thead>
    <tbody>
      {"".join(body_rows) if body_rows else '<tr><td colspan="9">没有记录</td></tr>'}
    </tbody>
  </table>

  <footer>
    复核方式：<code>python -m agentjudge audit verify --db &lt;db&gt; --anchor &lt;tail.anchor&gt;</code><br>
    本文件由 AgentJudge 生成，记录顺序即链顺序；任一条被改动都会导致校验失败。
  </footer>
</body>
</html>
"""


def write_html(
    path: str | Path,
    records: Iterable[ChainRecord],
    *,
    verification: VerifyResult | None = None,
    policy_version: str = "",
) -> Path:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        records_to_html(records, verification=verification, policy_version=policy_version),
        encoding="utf-8",
    )
    return target


__all__ = [
    "CSV_HEADER",
    "record_summary",
    "record_risk",
    "record_decision_id",
    "records_to_csv",
    "records_to_html",
    "write_csv",
    "write_html",
]
