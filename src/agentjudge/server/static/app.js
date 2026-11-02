/* 鉴行 · AgentJudge 工作台前端（零依赖） */
'use strict';

const state = {
  policy: null,
  sessions: [],
  sessionId: null,
  detail: null,
  metrics: null,
  pending: [],
  verify: null,
  token: localStorage.getItem('aj_token') || '',
  source: null,
  refreshTimer: null,
};

const $ = (id) => document.getElementById(id);
const esc = (value) =>
  String(value ?? '').replace(/[&<>"']/g, (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch]));
const fmtTime = (ts) =>
  ts ? new Date(ts * 1000).toLocaleTimeString('zh-CN', { hour12: false }) : '';
const pct = (value) => `${(Number(value || 0) * 100).toFixed(1)}%`;

async function api(path, { method = 'GET', body, raw = false } = {}) {
  const headers = { 'Content-Type': 'application/json' };
  if (state.token) headers.Authorization = `Bearer ${state.token}`;
  const res = await fetch(path, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
  });
  if (res.status === 401) {
    const token = window.prompt('需要访问 Token（启动时 --token 或 AGENTJUDGE_TOKEN）');
    if (token) {
      state.token = token.trim();
      localStorage.setItem('aj_token', state.token);
      return api(path, { method, body, raw });
    }
    throw new Error('unauthorized');
  }
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`${res.status} ${text}`);
  }
  return raw ? res : res.json();
}

/* ---------------- 顶栏 ---------------- */
async function loadHealth() {
  try {
    const health = await api('/api/v1/health');
    $('chip-policy').textContent = health.policy;
    $('chip-mode').textContent = health.mode === 'enforce' ? '模式：拦截' : '模式：监控';
    $('chip-mode').className = `chip ${health.mode === 'enforce' ? 'ok' : 'warn'}`;
    $('footer-right').textContent = `v${health.version} · ${health.watcher} · ${health.sessions} 会话`;
  } catch (err) {
    setTicker(`连接失败：${err.message}`, true);
  }
}

async function loadPolicy() {
  try {
    const policy = await api('/api/v1/policy');
    state.policy = policy;
    $('chip-policy').textContent = `${policy.name}@${policy.version} · ${policy.rule_count} 规则`;
  } catch (err) {
    /* 忽略 */
  }
}

/* ---------------- 会话 ---------------- */
async function loadSessions({ keepSelection = true } = {}) {
  const data = await api('/api/v1/sessions?limit=40');
  state.sessions = data.sessions || [];
  renderSessions();
  if (!state.sessions.length) {
    state.sessionId = null;
    renderTimeline(null);
    return;
  }
  const exists = keepSelection && state.sessions.some((s) => s.session_id === state.sessionId);
  if (!exists) {
    await selectSession(state.sessions[0].session_id);
  }
}

function renderSessions() {
  const box = $('session-list');
  const onlyRisky = $('only-risky').checked;
  const items = onlyRisky
    ? state.sessions.filter((s) => (s.counts.deny || 0) + (s.counts.escalate || 0) > 0)
    : state.sessions;
  if (!items.length) {
    box.innerHTML = `<div class="empty small">${onlyRisky ? '暂无异常会话' : '暂无会话'}</div>`;
    return;
  }
  box.innerHTML = items
    .map((s) => {
      const active = s.session_id === state.sessionId ? ' active' : '';
      const risk = Math.min(100, s.max_risk || 0);
      return `<button class="session${active}" data-sid="${esc(s.session_id)}">
        <div class="sid"><span>${esc(s.session_id)}</span><span class="muted">${s.total_steps} 步</span></div>
        <div class="meta">
          <span class="allow">放行 ${s.counts.allow}</span>
          <span class="deny">拒绝 ${s.counts.deny}</span>
          <span class="escalate">复核 ${s.counts.escalate}</span>
        </div>
        <div class="risk-bar"><span style="width:${risk}%"></span></div>
      </button>`;
    })
    .join('');
  box.querySelectorAll('.session').forEach((el) => {
    el.addEventListener('click', () => selectSession(el.dataset.sid));
  });
}

async function selectSession(sessionId) {
  state.sessionId = sessionId;
  renderSessions();
  try {
    state.detail = await api(`/api/v1/sessions/${encodeURIComponent(sessionId)}`);
  } catch (err) {
    state.detail = null;
  }
  renderTimeline(state.detail);
}

/* ---------------- 时间线 ---------------- */
function argsPreview(args) {
  if (!args || !Object.keys(args).length) return '';
  if (args.command) return `$ ${args.command}`;
  if (args.path) return `path: ${args.path}`;
  if (args.url) return `${args.method || 'GET'} ${args.url}`;
  if (args.content) return `content: ${args.content}`;
  return JSON.stringify(args, null, 2);
}

function renderTimeline(detail) {
  const box = $('timeline');
  if (!detail) {
    $('tl-title').textContent = '时间线';
    $('tl-meta').textContent = '';
    box.innerHTML = `<div class="empty"><strong>还没有可展示的会话</strong>
      <p>点击右上角「运行演示」生成一条真实的凭据外泄链，或通过 API 发起裁决。</p>
      <code>curl -X POST ${location.origin}/api/v1/intercept \\
  -H 'Content-Type: application/json' \\
  -d '{"tool":"shell.exec","args":{"command":"rm -rf ~"},"session_id":"demo"}'</code></div>`;
    return;
  }
  $('tl-title').textContent = `时间线 · ${detail.session_id}`;
  $('tl-meta').textContent = `agent=${detail.agent_id} · 放行 ${detail.counts.allow} / 拒绝 ${detail.counts.deny} / 复核 ${detail.counts.escalate}`;

  const timeline = detail.timeline || [];
  if (!timeline.length) {
    box.innerHTML = '<div class="empty small">该会话暂无裁决记录</div>';
    return;
  }
  box.innerHTML = timeline
    .map((item) => {
      const decision = item.decision || {};
      const action = decision.action || item.action || 'allow';
      const risk = decision.risk ?? item.risk ?? 0;
      const call = item.call || {};
      const preview = argsPreview(call.args || {});
      const reasons = (decision.reasons || [])
        .map((r) => `<span class="tag hit">${esc(r.rule_id)} ${esc(r.title)}</span>`)
        .join('');
      const edges = [];
      (decision.findings || []).forEach((f) => {
        (f.evidence && f.evidence.edges ? f.evidence.edges : []).forEach((edge) => {
          edges.push(
            `<span class="tag flow">数据流 #${edge.source_step} ${esc(edge.source_tool)} → 本步（${esc(
              (edge.labels || []).join(', ')
            )}）</span>`
          );
        });
      });
      const quarantine = decision.quarantined ? '<span class="badge quarantine">隔离</span>' : '';
      const review =
        decision.review_status && decision.review_status !== 'auto'
          ? `<span class="badge ${decision.review_status === 'approved' ? 'allow' : 'deny'}">${
              decision.review_status === 'approved' ? '已通过' : '已拒绝'
            }</span>`
          : '';
      const watcher = decision.watcher
        ? `<div class="explain">语义研判：${esc(decision.watcher.verdict)}（置信度 ${Number(
            decision.watcher.confidence || 0
          ).toFixed(2)}，${decision.watcher.rounds} 轮）${esc(decision.watcher.summary || '')}</div>`
        : '';
      return `<article class="step ${esc(action)}">
        <div class="step-head">
          <span class="idx">#${String(item.index || 0).padStart(2, '0')}</span>
          <span class="tool">${esc(item.tool || call.tool || '')}</span>
          <span class="badge ${esc(action)}">${esc(action.toUpperCase())}</span>
          ${quarantine}${review}
          <span class="risk">风险 <b>${risk}</b></span>
          <span class="time">${fmtTime(item.ts)}</span>
        </div>
        ${preview ? `<pre class="code">${esc(preview)}</pre>` : ''}
        ${reasons || edges ? `<div class="reasons">${reasons}${edges.join('')}</div>` : ''}
        ${decision.explanation ? `<div class="explain">${esc(decision.explanation)}</div>` : ''}
        ${watcher}
        <details><summary>证据与守卫耗时</summary><pre class="code">${esc(
          JSON.stringify(
            { guards: decision.guards || [], findings: decision.findings || [], decision_id: decision.decision_id },
            null,
            2
          )
        )}</pre></details>
      </article>`;
    })
    .join('');
}

/* ---------------- 指标 / 复核 / 审计 ---------------- */
async function loadMetrics() {
  try {
    const stats = await api('/api/v1/metrics');
    state.metrics = stats;
    renderMetrics(stats);
  } catch (err) {
    /* 忽略 */
  }
}

function renderMetrics(stats) {
  const metrics = stats.metrics || {};
  const latency = metrics.latency_ms || {};
  const cards = [
    ['裁决总数', metrics.total_decisions ?? 0, ''],
    ['拒绝率', pct(metrics.deny_rate), ''],
    ['延迟 p95', latency.p95 ?? 0, 'ms'],
    ['误判闭环', (metrics.by_action && metrics.by_action.escalate) || 0, '待复核'],
    ['审计记录', (stats.store && stats.store.records) || 0, '条'],
    ['语义研判', (metrics.watcher && metrics.watcher.calls) || 0, '次'],
  ];
  $('metrics').innerHTML = cards
    .map(
      ([key, value, unit]) =>
        `<div class="metric"><div class="k">${esc(key)}</div><div class="v">${esc(value)} <small>${esc(unit)}</small></div></div>`
    )
    .join('');
}

async function loadPending() {
  try {
    const data = await api('/api/v1/reviews/pending');
    state.pending = data.reviews || [];
    renderPending();
  } catch (err) {
    /* 忽略 */
  }
}

function renderPending() {
  $('review-count').textContent = String(state.pending.length);
  const box = $('review-list');
  if (!state.pending.length) {
    box.innerHTML = '<div class="empty small">队列为空</div>';
    return;
  }
  box.innerHTML = state.pending
    .map((d) => {
      const first = (d.reasons || [])[0] || {};
      return `<div class="review">
        <div class="row1"><span>${esc(d.tool)}</span><span class="badge escalate">待复核</span><span class="muted">风险 ${d.risk}</span></div>
        <div class="why">${esc(first.title || d.explanation || '')}</div>
        <div class="row2">
          <button class="btn small" data-approve="${esc(d.decision_id)}">放行</button>
          <button class="btn small ghost" data-reject="${esc(d.decision_id)}">拒绝</button>
        </div>
      </div>`;
    })
    .join('');
  box.querySelectorAll('[data-approve]').forEach((btn) =>
    btn.addEventListener('click', () => submitReview(btn.dataset.approve, true))
  );
  box.querySelectorAll('[data-reject]').forEach((btn) =>
    btn.addEventListener('click', () => submitReview(btn.dataset.reject, false))
  );
}

async function submitReview(decisionId, approve) {
  try {
    await api(`/api/v1/reviews/${encodeURIComponent(decisionId)}`, {
      method: 'POST',
      body: { approve, reviewer: 'workbench', note: approve ? '人工放行' : '人工拒绝' },
    });
    setTicker(`${approve ? '已放行' : '已拒绝'} ${decisionId}`);
    await Promise.all([loadPending(), loadSessions(), loadMetrics()]);
  } catch (err) {
    setTicker(`复核失败：${err.message}`, true);
  }
}

async function verifyChain() {
  const chip = $('btn-verify');
  try {
    const result = await api('/api/v1/audit/verify');
    state.verify = result;
    chip.textContent = result.ok ? `审计链：通过 · ${result.records} 条` : `审计链：失败 · ${result.reason}`;
    chip.className = `chip chip-btn ${result.ok ? 'ok' : 'bad'}`;
    renderAudit(result);
    return result;
  } catch (err) {
    chip.textContent = '审计链：校验失败';
    chip.className = 'chip chip-btn bad';
    return null;
  }
}

function renderAudit(result) {
  const box = $('audit-box');
  if (!result) {
    box.innerHTML = '<span class="muted">校验失败</span>';
    return;
  }
  const tone = result.ok ? 'var(--allow)' : 'var(--deny)';
  box.innerHTML = `
    <div class="line"><span class="big" style="color:${tone}">${result.ok ? '链完整' : '链断裂'}</span>
      <span class="muted">${result.records} 条记录</span></div>
    <div class="line"><span class="muted">链尾指纹</span><span class="mono">${esc((result.chain_tail || '').slice(0, 24))}…</span></div>
    <div class="line"><span class="muted">独立尾锚</span><span class="mono">${result.anchor_present ? '已封存' : '未封存'}</span></div>
    <div class="mono" style="margin-top:6px;color:${result.ok ? 'var(--muted)' : 'var(--deny)'}">${esc(
      result.detail || result.anchor_detail || ''
    )}</div>
    ${result.ok ? '' : `<div class="mono" style="color:var(--deny)">断裂点 #${esc(result.broken_at)} · ${esc(result.reason)}</div>`}
    <div style="margin-top:8px"><button class="btn small" id="btn-seal">立即封存尾锚</button></div>`;
  const seal = $('btn-seal');
  if (seal) {
    seal.addEventListener('click', async () => {
      await api('/api/v1/audit/seal', { method: 'POST' });
      await verifyChain();
      setTicker('尾锚已封存');
    });
  }
}

/* ---------------- 技能体检 ---------------- */
async function inspectSkill() {
  const path = $('skill-path').value.trim();
  if (!path) return;
  const box = $('skill-result');
  box.innerHTML = '<span class="muted">分析中…</span>';
  try {
    const data = await api('/api/v1/skills/inspect', { method: 'POST', body: { path } });
    renderSkill(data.report);
  } catch (err) {
    box.innerHTML = `<span class="muted">体检失败：${esc(err.message)}</span>`;
  }
}

function renderSkill(report) {
  if (!report) return;
  const rows = (report.matrix || [])
    .filter((row) => row.declared || row.observed)
    .map((row) => {
      const drift = { match: '一致', undeclared: '未声明', contradicted: '与声明相反', unmet: '声明未实测' }[row.drift] || row.drift;
      const cls = row.drift === 'match' ? 'match' : row.drift === 'unmet' ? 'no' : 'drift';
      return `<tr><td>${esc(row.label)}</td><td class="${row.declared ? 'yes' : 'no'}">${row.declared ? '是' : '—'}</td>
        <td class="${row.observed ? 'yes' : 'no'}">${row.observed ? '是' : '—'}</td>
        <td class="${cls}">${esc(drift)}</td></tr>`;
    })
    .join('');
  const drift = (report.drift || [])
    .slice(0, 5)
    .map((item) => `<div class="explain">· ${esc(item.label)}：${esc(item.detail)}</div>`)
    .join('');
  $('skill-result').innerHTML = `
    <div class="skill-head">
      <span class="mono">${esc(report.name)}</span>
      <span class="trust ${esc(report.trust)}">${esc(report.trust)}</span>
      <span class="muted">${report.score}/100</span>
    </div>
    <table><thead><tr><th>能力</th><th>声明</th><th>实测</th><th>结论</th></tr></thead><tbody>${rows}</tbody></table>
    ${drift}`;
}

/* ---------------- 演示 / 评测 / 实时 ---------------- */
async function runDemo() {
  const btn = $('btn-demo');
  btn.disabled = true;
  btn.textContent = '演练中…';
  try {
    const data = await api('/api/v1/demo', { method: 'POST' });
    setTicker(`演示完成：第 ${data.blocked_at ?? '-'} 步被拦截，会话 ${data.session_id}`);
    await loadSessions({ keepSelection: false });
    await selectSession(data.session_id);
    await Promise.all([loadMetrics(), loadPending()]);
    await verifyChain();
  } catch (err) {
    setTicker(`演示失败：${err.message}`, true);
  } finally {
    btn.disabled = false;
    btn.textContent = '运行演示';
  }
}

async function runEval() {
  const btn = $('btn-eval');
  btn.disabled = true;
  btn.textContent = '评测中…';
  try {
    const report = await api('/api/v1/eval', { method: 'POST' });
    const attacks = report.attacks || {};
    const benign = report.benign || {};
    const text = `评测：拦截 ${attacks.intercepted}/${attacks.total}，ASR ${pct(attacks.asr)}，良性完成率 ${pct(
      benign.completion
    )}，FPR ${pct(benign.fpr)}，p95 ${(report.latency_ms || {}).p95}ms`;
    showBanner(text);
    setTicker(text);
    await Promise.all([loadSessions(), loadMetrics()]);
  } catch (err) {
    setTicker(`评测失败：${err.message}`, true);
  } finally {
    btn.disabled = false;
    btn.textContent = '跑评测';
  }
}

function showBanner(text) {
  const banner = document.createElement('div');
  banner.className = 'step allow';
  banner.innerHTML = `<div class="step-head"><span class="idx">EVAL</span><span class="tool">评测结果</span>
    <span class="badge allow">完成</span></div><div class="explain">${esc(text)}</div>`;
  $('timeline').prepend(banner);
  setTimeout(() => banner.remove(), 12000);
}

function setTicker(text, error = false) {
  const el = $('ticker');
  el.innerHTML = `<b>${new Date().toLocaleTimeString('zh-CN', { hour12: false })}</b> ${esc(text)}`;
  el.style.color = error ? 'var(--deny)' : 'var(--muted)';
}

function scheduleRefresh() {
  if (state.refreshTimer) return;
  state.refreshTimer = setTimeout(async () => {
    state.refreshTimer = null;
    await Promise.all([loadSessions(), loadMetrics(), loadPending()]);
    if (state.sessionId) {
      try {
        state.detail = await api(`/api/v1/sessions/${encodeURIComponent(state.sessionId)}`);
        renderTimeline(state.detail);
      } catch (err) {
        /* 忽略 */
      }
    }
  }, 400);
}

function connectEvents() {
  if (state.source) state.source.close();
  const url = state.token ? `/api/v1/events?token=${encodeURIComponent(state.token)}` : '/api/v1/events';
  const source = new EventSource(url);
  state.source = source;
  source.onmessage = (event) => {
    try {
      const data = JSON.parse(event.data);
      if (data.type === 'decision') {
        setTicker(`${data.action?.toUpperCase()} · ${data.tool} · ${data.session_id}（风险 ${data.risk}）`);
      } else if (data.type === 'review') {
        setTicker(`人工复核：${data.review_status} · ${data.decision_id}`);
      } else if (data.type === 'observe') {
        setTicker(`结果侧复核：${data.quarantined ? '已隔离' : '通过'}`);
      }
      scheduleRefresh();
    } catch (err) {
      /* 忽略 */
    }
  };
  source.onerror = () => {
    $('chip-live').className = 'chip warn';
    setTicker('实时连接断开，正在重连…', true);
  };
  source.onopen = () => {
    $('chip-live').className = 'chip live';
  };
}

/* ---------------- 启动 ---------------- */
async function boot() {
  $('btn-verify').addEventListener('click', verifyChain);
  $('btn-refresh').addEventListener('click', () => loadSessions());
  $('btn-demo').addEventListener('click', runDemo);
  $('btn-eval').addEventListener('click', runEval);
  $('btn-skill').addEventListener('click', inspectSkill);
  $('only-risky').checked = localStorage.getItem('aj_only_risky') === '1';
  $('only-risky').addEventListener('change', (event) => {
    localStorage.setItem('aj_only_risky', event.target.checked ? '1' : '0');
    renderSessions();
  });
  $('skill-path').addEventListener('keydown', (event) => {
    if (event.key === 'Enter') inspectSkill();
  });

  await loadHealth();
  await loadPolicy();
  await verifyChain();
  await loadSessions({ keepSelection: false });
  await loadMetrics();
  await loadPending();
  // ?nolive=1 用于无头截图/离线演示：不建立 SSE 长连接
  if (!new URLSearchParams(location.search).has('nolive')) {
    connectEvents();
  }
  setInterval(loadHealth, 30000);
}

document.addEventListener('DOMContentLoaded', boot);
