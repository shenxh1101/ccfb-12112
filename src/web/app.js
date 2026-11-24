/** 面板主逻辑：极简 hash 路由 + 四个页面模块 */
import { renderPayloadsPage } from './pages/payloads.js';
import { renderConfigPage } from './pages/config.js';
import { renderScanPage } from './pages/scan.js';
import { renderRemediationPage } from './pages/remediation.js';

export const view = document.getElementById('view');
export const toastEl = document.getElementById('toast');

export function toast(message, tone = '') {
  toastEl.textContent = message;
  toastEl.className = `toast ${tone}`;
  toastEl.hidden = false;
  clearTimeout(toast._t);
  toast._t = setTimeout(() => { toastEl.hidden = true; }, 3200);
}

/** 统一 fetch 封装 */
export async function api(path, options = {}) {
  const res = await fetch(path, {
    headers: { 'Content-Type': 'application/json' },
    ...options,
    body: options.body ? JSON.stringify(options.body) : undefined
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `请求失败 ${res.status}`);
  return data;
}

export function esc(s) {
  return String(s ?? '')
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

const PAGES = {
  payloads: renderPayloadsPage,
  config: renderConfigPage,
  scan: renderScanPage,
  remediation: renderRemediationPage
};

async function route() {
  const page = location.hash.replace('#/', '') || 'payloads';
  document.querySelectorAll('.tab').forEach(b =>
    b.classList.toggle('active', b.dataset.page === page));
  view.innerHTML = '<div class="empty"><span class="spinner"></span> 加载中…</div>';
  try {
    await (PAGES[page] || renderPayloadsPage)();
  } catch (e) {
    view.innerHTML = `<div class="empty">页面加载失败: ${esc(e.message)}</div>`;
  }
}

document.getElementById('tabs').addEventListener('click', e => {
  const btn = e.target.closest('.tab');
  if (btn) location.hash = `#/${btn.dataset.page}`;
});
window.addEventListener('hashchange', route);
route();
