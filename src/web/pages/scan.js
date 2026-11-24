import { api, esc, view, toast } from '../app.js';
import { STATUS_LABEL } from './meta.js';

let state = { statusFilter: '', categoryFilter: '', report: null, history: [] };

export async function renderScanPage() {
  state.history = (await api('/api/scans')).scans;

  view.innerHTML = `
    <div class="page-head">
      <h2>扫描结果</h2>
      <div class="toolbar">
        <select id="history-select">
          <option value="">— 选择历史扫描 —</option>
          ${state.history.map(id => `<option value="${esc(id)}">${esc(id)}</option>`).join('')}
        </select>
        <select id="cat-filter">
          <option value="">全部分类</option>
        </select>
        <select id="status-filter">
          <option value="">全部状态</option>
          <option value="pass">已挡住</option>
          <option value="bypass">脚本执行（绕过）</option>
          <option value="clobbered">DOM Clobbering</option>
          <option value="css-exfil">CSS 外联外泄</option>
          <option value="css-style-survive">危险样式存活</option>
          <option value="error">检测异常</option>
        </select>
        <button class="btn" id="scan-btn">启动全量扫描</button>
      </div>
    </div>
    <div id="scan-body"><div class="empty">尚未选择扫描记录。点击「启动全量扫描」在无头 Chrome 沙箱中真实执行全部载荷。</div></div>
  `;

  const catSel = document.getElementById('cat-filter');
  document.getElementById('status-filter').addEventListener('change', e => {
    state.statusFilter = e.target.value;
    drawResults();
  });
  catSel.addEventListener('change', e => {
    state.categoryFilter = e.target.value;
    drawResults();
  });
  document.getElementById('history-select').addEventListener('change', async e => {
    if (!e.target.value) return;
    state.report = await api(`/api/scans/${e.target.value}`);
    fillCategoryFilter();
    drawResults();
  });
  document.getElementById('scan-btn').addEventListener('click', runScan);

  // 从载荷页试跑跳转过来时自动加载最新记录
  if (window.__lastScanId) {
    state.report = await api(`/api/scans/${window.__lastScanId}`);
    window.__lastScanId = null;
    fillCategoryFilter();
    drawResults();
  }
}

function fillCategoryFilter() {
  const cats = [...new Set(state.report.results.map(r => r.category))];
  document.getElementById('cat-filter').innerHTML =
    '<option value="">全部分类</option>' +
    cats.map(c => `<option value="${esc(c)}">${esc(c)}</option>`).join('');
}

async function runScan() {
  const body = document.getElementById('scan-body');
  body.innerHTML = '<div class="empty"><span class="spinner"></span> 正在拉起无头 Chrome 并逐条执行载荷（约 1-2 分钟）…</div>';
  try {
    state.report = await api('/api/scan', { method: 'POST', body: {} });
    state.history = (await api('/api/scans')).scans;
    fillCategoryFilter();
    drawResults();
    toast(`扫描完成：${state.report.blocked} 挡住 / ${state.report.bypassed} 绕过`,
      state.report.bypassed ? 'err' : 'ok');
  } catch (e) {
    body.innerHTML = `<div class="empty">扫描失败：${esc(e.message)}</div>`;
  }
}

function drawResults() {
  if (!state.report) return;
  const r = state.report;
  const el = document.getElementById('scan-body');

  const rows = r.results.filter(x =>
    (!state.statusFilter || x.status === state.statusFilter) &&
    (!state.categoryFilter || x.category === state.categoryFilter));

  el.innerHTML = `
    <div class="cards">
      <div class="card"><div class="num">${r.total}</div><div class="lbl">载荷总数</div></div>
      <div class="card"><div class="num" style="color:var(--ok)">${r.blocked}</div><div class="lbl">已挡住</div></div>
      <div class="card"><div class="num" style="color:var(--danger)">${r.bypassed}</div><div class="lbl">未挡住（绕过/clobber/外泄）</div></div>
      <div class="card"><div class="num" style="color:var(--warn)">${r.errors}</div><div class="lbl">检测异常</div></div>
    </div>
    <p class="item-meta">扫描 ${esc(r.id)} · 配置 ${esc(r.configName)} · ${esc(r.startedAt)}</p>
    <div class="result-list">
      ${rows.map(x => resultCard(x)).join('')}
    </div>
  `;
}

function resultCard(x) {
  const tone = x.status === 'pass' ? 'ok' : (x.status === 'error' ? 'warn' : 'danger');
  return `
    <div class="item">
      <div class="item-row">
        <span class="badge ${tone}">${esc(STATUS_LABEL[x.status] || x.status)}</span>
        <div class="item-main">
          <div class="item-title">${esc(x.payloadId)} · ${esc(x.name)}</div>
          <div class="item-meta">${esc(x.category)} · 期望 ${esc(x.expectation)} · ${esc(x.conclusion)}</div>
        </div>
      </div>
      <details>
        <summary>净化输出 / 决策 trace / 证据</summary>
        <p class="item-meta" style="margin-top:8px">净化后 HTML：</p>
        <div class="vector-box">${esc(x.sanitized || '(空)')}</div>
        ${x.evidence.network.length ? `
          <p class="item-meta" style="margin-top:8px">外联请求（外泄证据）：</p>
          <div class="vector-box">${x.evidence.network.map(n => esc(n.url)).join('\n')}</div>` : ''}
        ${x.evidence.clobberDetail ? `
          <p class="item-meta" style="margin-top:8px">clobber 判定：<code>${esc(JSON.stringify(x.evidence.clobberDetail))}</code></p>` : ''}
        ${x.evidence.events.length ? `
          <p class="item-meta" style="margin-top:8px">脚本执行事件：</p>
          <div class="vector-box">${x.evidence.events.map(e => esc(`${e.kind}: ${e.detail}`)).join('\n')}</div>` : ''}
        <p class="item-meta" style="margin-top:8px">决策 trace（哪条规则放行/拒绝，共 ${x.trace.length} 条）：</p>
        <div class="scroll-x">
          ${x.trace.map(t => `
            <div class="trace-line ${t.action}">
              <span class="trace-rule">${esc(t.ruleId)}</span>
              · <span class="trace-target">${esc(t.target)}</span>
              · ${esc(t.action)} — ${esc(t.reason)}
            </div>`).join('')}
        </div>
      </details>
    </div>
  `;
}
