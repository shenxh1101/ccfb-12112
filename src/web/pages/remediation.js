import { api, esc, view, toast } from '../app.js';

export async function renderRemediationPage() {
  const { scans } = await api('/api/scans');

  view.innerHTML = `
    <div class="page-head">
      <h2>修复建议</h2>
      <div class="toolbar">
        <select id="scan-select">
          <option value="">— 选择扫描记录 —</option>
          ${scans.map(id => `<option value="${esc(id)}">${esc(id)}</option>`).join('')}
        </select>
      </div>
    </div>
    <div id="advice-body"><div class="empty">选择一条存在绕过的扫描记录，系统会按根因聚合生成可一键应用的配置补丁。</div></div>
  `;

  document.getElementById('scan-select').addEventListener('change', async e => {
    if (!e.target.value) return;
    await loadAdvice(e.target.value);
  });

  // 默认选最新一条
  if (scans.length) {
    const sel = document.getElementById('scan-select');
    sel.value = scans[0];
    await loadAdvice(scans[0]);
  }
}

async function loadAdvice(scanId) {
  const body = document.getElementById('advice-body');
  body.innerHTML = '<div class="empty"><span class="spinner"></span> 分析绕过根因…</div>';
  try {
    const [scan, { advice }] = await Promise.all([
      api(`/api/scans/${scanId}`),
      api(`/api/remediation/${scanId}`)
    ]);

    const bypassed = scan.results.filter(r => r.status !== 'pass' && r.status !== 'error');
    if (!bypassed.length) {
      body.innerHTML = `
        <div class="item">
          <div class="item-title" style="color:var(--ok)">✓ 该次扫描全部载荷已被挡住，无需修复</div>
          <p class="item-meta" style="margin-top:8px">共 ${scan.total} 条载荷，配置 ${esc(scan.configName)}。可在「净化器配置」页继续做收紧演练。</p>
        </div>`;
      return;
    }

    body.innerHTML = `
      <div class="item" style="margin-bottom:14px">
        <div class="item-title">本次有 ${bypassed.length} 条载荷未挡住，聚合出 ${advice.length} 条修复建议</div>
        <p class="item-meta" style="margin-top:6px">每条建议对应具体 ruleId 与配置 diff；应用后会自动用新配置重新扫描并对比结果。</p>
      </div>
      <div class="result-list">
        ${advice.map((a, i) => `
          <div class="item">
            <div class="item-row">
              <div class="item-main">
                <div class="item-title">${i + 1}. ${esc(a.title)}</div>
                <div class="item-meta" style="margin-top:4px">${esc(a.reason)}</div>
                <div class="item-meta" style="margin-top:4px">
                  关联 ruleId：${a.ruleIds.map(r => `<span class="badge cat">${esc(r)}</span>`).join(' ')}
                </div>
              </div>
              <button class="btn ok apply-btn" data-advice="${esc(a.id)}">一键应用并重新扫描</button>
            </div>
          </div>
        `).join('')}
      </div>
      <div id="rescan-result" style="margin-top:18px"></div>
    `;

    body.querySelectorAll('.apply-btn').forEach(btn => {
      btn.addEventListener('click', () => applyAndRescan(scanId, btn.dataset.advice, btn));
    });
  } catch (e) {
    body.innerHTML = `<div class="empty">加载失败：${esc(e.message)}</div>`;
  }
}

async function applyAndRescan(scanId, adviceId, btn) {
  btn.disabled = true;
  btn.textContent = '应用中…';
  const out = document.getElementById('rescan-result');
  try {
    const res = await api('/api/remediation/apply', {
      method: 'POST',
      body: { scanId, adviceId, rescan: true }
    });
    const before = res.rescan ? `${res.rescan.total} 条载荷：挡住 ${res.rescan.blocked} / 未挡住 ${res.rescan.bypassed}` : '';
    out.innerHTML = `
      <div class="item" style="border-left:3px solid var(--ok)">
        <div class="item-title" style="color:var(--ok)">✓ 已应用「${esc(res.advice.title)}」并完成重新扫描</div>
        <p class="item-meta" style="margin-top:6px">重扫结果：${esc(before)}</p>
        <p class="item-meta">配置已持久化，可在「净化器配置」页查看 diff 或导出。</p>
        <button class="btn secondary" id="goto-scan">查看完整重扫结果</button>
      </div>`;
    document.getElementById('goto-scan').addEventListener('click', () => {
      window.__lastScanId = res.rescan.id;
      location.hash = '#/scan';
    });
    toast('修复已应用并重扫', 'ok');
  } catch (e) {
    btn.disabled = false;
    btn.textContent = '一键应用并重新扫描';
    toast(`应用失败：${e.message}`, 'err');
  }
}
