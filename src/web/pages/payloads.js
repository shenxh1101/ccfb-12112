import { api, esc, view, toast } from '../app.js';

let state = { category: '', data: null };

export async function renderPayloadsPage() {
  if (!state.data) state.data = await api('/api/payloads');
  const { categories, payloads, statusMeta } = state.data;

  view.innerHTML = `
    <div class="page-head">
      <h2>载荷库（${payloads.length} 条）</h2>
      <div class="toolbar">
        <select id="cat-filter">
          <option value="">全部分类</option>
          ${categories.map(c => `<option value="${c.key}" ${state.category === c.key ? 'selected' : ''}>${esc(c.name)}（${c.count}）</option>`).join('')}
        </select>
        <button class="btn secondary" id="run-one">试跑选中载荷</button>
      </div>
    </div>
    <div class="cards">
      ${categories.map(c => {
        const n = payloads.filter(p => p.category === c.key).length;
        return `<div class="card"><div class="num">${n}</div><div class="lbl">${esc(c.name)}</div></div>`;
      }).join('')}
    </div>
    <div class="payload-list" id="payload-list"></div>
  `;

  const listEl = document.getElementById('payload-list');
  const draw = () => {
    const rows = state.category ? payloads.filter(p => p.category === state.category) : payloads;
    listEl.innerHTML = rows.map(p => `
      <div class="item" data-id="${p.id}">
        <div class="item-row">
          <input type="checkbox" class="pick" value="${p.id}">
          <div class="item-main">
            <div class="item-title">${esc(p.id)} · ${esc(p.name)}</div>
            <div class="item-meta">
              <span class="badge cat">${esc(categories.find(c => c.key === p.category)?.name || p.category)}</span>
              期望：${esc(p.expectation)}
              ${p.ref ? `· 参考：${esc(p.ref)}` : ''}
            </div>
          </div>
        </div>
        <details>
          <summary>查看原始向量 / 原理 / 检测方式</summary>
          <div class="vector-box">${esc(p.vector)}</div>
          <p class="item-meta" style="margin-top:8px">${esc(p.description)}</p>
          <p class="item-meta">检测：<code>${esc(JSON.stringify(p.detect))}</code> · 注入上下文：<code>${esc(p.context)}</code></p>
        </details>
      </div>
    `).join('');
  };
  draw();

  document.getElementById('cat-filter').addEventListener('change', e => {
    state.category = e.target.value;
    draw();
  });

  document.getElementById('run-one').addEventListener('click', async () => {
    const ids = [...listEl.querySelectorAll('.pick:checked')].map(c => c.value);
    if (!ids.length) return toast('请先勾选要试跑的载荷', 'err');
    toast(`正在沙箱中执行 ${ids.length} 条载荷…`);
    try {
      const report = await api('/api/scan', { method: 'POST', body: { payloadIds: ids } });
      location.hash = '#/scan';
      window.__lastScanId = report.id;
      toast(`试跑完成：${report.blocked} 挡住 / ${report.bypassed} 绕过`, report.bypassed ? 'err' : 'ok');
    } catch (e) {
      toast(e.message, 'err');
    }
  });
}
