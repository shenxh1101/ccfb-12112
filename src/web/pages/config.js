import { api, esc, view, toast } from '../app.js';

export async function renderConfigPage() {
  const cfg = await api('/api/config');

  view.innerHTML = `
    <div class="page-head">
      <h2>净化器配置 <span class="badge muted">schema v${cfg.schemaVersion} · ${esc(cfg.name)}</span></h2>
      <div class="toolbar">
        <button class="btn secondary" id="export-btn">导出 JSON</button>
        <label class="btn secondary" style="cursor:pointer">导入 JSON
          <input type="file" id="import-file" accept=".json,application/json" hidden>
        </label>
        <button class="btn secondary" id="strict-css-btn">切换 strict-css 预设</button>
        <button class="btn danger" id="reset-btn">恢复严格默认</button>
        <button class="btn ok" id="save-btn">保存配置</button>
      </div>
    </div>

    <div class="config-section">
      <h3>标签白名单（${cfg.tags.allowed.length}）</h3>
      <div class="chip-list" id="tag-chips">
        ${cfg.tags.allowed.map(t => `<span class="chip">${esc(t)}<button data-remove="tag" data-val="${esc(t)}">×</button></span>`).join('')}
      </div>
      <div class="add-row">
        <input id="new-tag" placeholder="新增标签名，如 mark">
        <button class="btn secondary" id="add-tag">添加</button>
      </div>
      <div class="switch-row" style="margin-top:14px">
        <label>整树丢弃清单（dropWithContent，标签与子内容一起移除）</label>
        <span class="mono item-meta">${cfg.tags.dropWithContent.map(esc).join(', ')}</span>
      </div>
    </div>

    <div class="config-section">
      <h3>属性策略</h3>
      <div class="switch-row">
        <label>全局通用属性</label>
        <span class="mono">${cfg.attrs.global.map(esc).join(', ')}</span>
      </div>
      <div class="switch-row">
        <label>全局丢弃 name 属性（DOM clobbering 主入口）</label>
        <span class="badge ${cfg.attrs.dropNameAttr ? 'ok' : 'danger'}">${cfg.attrs.dropNameAttr ? '开启' : '关闭'}</span>
      </div>
      <div class="switch-row">
        <label>id 策略（默认 fail-closed 关闭）</label>
        <span>
          <span class="badge ${cfg.attrs.id.enabled ? 'warn' : 'ok'}">${cfg.attrs.id.enabled ? '启用，需过正则+deny' : '全部拒绝'}</span>
          <code class="item-meta">${esc(cfg.attrs.id.pattern)}</code>
        </span>
      </div>
      <div class="switch-row">
        <label>含控制字符的属性名/值整体拒绝</label>
        <span class="badge ${cfg.attrs.rejectControlChars ? 'ok' : 'danger'}">${cfg.attrs.rejectControlChars ? '开启' : '关闭'}</span>
      </div>
      <details>
        <summary>按标签限定的属性白名单（${Object.keys(cfg.attrs.perTag).length} 个标签）</summary>
        <pre class="vector-box">${esc(JSON.stringify(cfg.attrs.perTag, null, 2))}</pre>
      </details>
    </div>

    <div class="config-section">
      <h3>URL / 协议</h3>
      <div class="switch-row">
        <label>允许协议</label>
        <span class="mono">${cfg.url.allowedProtocols.map(esc).join(' ')}</span>
      </div>
      <div class="switch-row">
        <label>img 上 data: 允许的图片 MIME（svg+xml 明确排除）</label>
        <span class="mono">${cfg.url.allowedDataMime.map(esc).join(', ')}</span>
      </div>
      <div class="switch-row">
        <label>允许相对 URL</label>
        <span class="badge ${cfg.url.allowRelative ? 'ok' : 'danger'}">${cfg.url.allowRelative ? '是' : '否'}</span>
      </div>
      <div class="switch-row">
        <label>target=_blank 强制 rel=noopener noreferrer</label>
        <span class="badge ${cfg.url.enforceNoopener ? 'ok' : 'danger'}">${cfg.url.enforceNoopener ? '开启' : '关闭'}</span>
      </div>
    </div>

    <div class="config-section">
      <h3>CSS（历史绕过点，默认全关）</h3>
      <div class="switch-row">
        <label>style 属性</label>
        <span class="badge ${cfg.css.allowStyleAttr ? 'warn' : 'ok'}">${cfg.css.allowStyleAttr ? '开启（strict 白名单）' : '关闭'}</span>
      </div>
      <div class="switch-row">
        <label>&lt;style&gt; 标签</label>
        <span class="badge ${cfg.css.allowStyleTag ? 'danger' : 'ok'}">${cfg.css.allowStyleTag ? '开启' : '关闭'}</span>
      </div>
      <details>
        <summary>strict-css 允许的 CSS 属性（${cfg.css.strict.allowedProperties.length}）与危险值特征</summary>
        <p class="item-meta">属性：</p>
        <div class="chip-list">${cfg.css.strict.allowedProperties.map(p => `<span class="chip">${esc(p)}</span>`).join('')}</div>
        <p class="item-meta" style="margin-top:8px">危险值：<code>${cfg.css.strict.forbiddenValuePatterns.map(esc).join(' ')}</code></p>
      </details>
    </div>

    <div class="config-section">
      <h3>原始 JSON（可直接编辑后保存）</h3>
      <textarea id="raw-json" rows="14">${esc(JSON.stringify(cfg, null, 2))}</textarea>
    </div>
  `;

  // 标签增删（只改本地 JSON 文本，保存时统一提交，避免多份状态不一致）
  const patchConfig = (mutator) => {
    const current = JSON.parse(document.getElementById('raw-json').value);
    mutator(current);
    document.getElementById('raw-json').value = JSON.stringify(current, null, 2);
    toast('已更新待保存配置，记得点「保存配置」');
  };

  document.getElementById('tag-chips').addEventListener('click', e => {
    if (e.target.dataset.remove !== 'tag') return;
    const val = e.target.dataset.val;
    patchConfig(c => { c.tags.allowed = c.tags.allowed.filter(t => t !== val); });
    e.target.closest('.chip').remove();
  });
  document.getElementById('add-tag').addEventListener('click', () => {
    const input = document.getElementById('new-tag');
    const t = input.value.trim().toLowerCase();
    if (!t) return;
    patchConfig(c => { if (!c.tags.allowed.includes(t)) c.tags.allowed.push(t); });
    input.value = '';
    renderConfigPage();
  });

  document.getElementById('save-btn').addEventListener('click', async () => {
    try {
      const body = JSON.parse(document.getElementById('raw-json').value);
      await api('/api/config', { method: 'PUT', body });
      toast('配置已保存', 'ok');
      renderConfigPage();
    } catch (e) {
      toast(`保存失败：${e.message}`, 'err');
    }
  });

  document.getElementById('reset-btn').addEventListener('click', async () => {
    if (!confirm('恢复严格默认配置？当前未保存的修改会丢失。')) return;
    await api('/api/config/reset', { method: 'POST' });
    toast('已恢复严格默认配置', 'ok');
    renderConfigPage();
  });

  document.getElementById('strict-css-btn').addEventListener('click', () => {
    const current = JSON.parse(document.getElementById('raw-json').value);
    current.css.allowStyleAttr = true;
    current.css.allowStyleTag = false;
    document.getElementById('raw-json').value = JSON.stringify(current, null, 2);
    toast('已在待保存配置中开启 strict-css（style 属性），保存后生效');
  });

  document.getElementById('export-btn').addEventListener('click', () => {
    const blob = new Blob([document.getElementById('raw-json').value], { type: 'application/json' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'sanitizer-config.json';
    a.click();
    URL.revokeObjectURL(a.href);
  });

  document.getElementById('import-file').addEventListener('change', async e => {
    const file = e.target.files[0];
    if (!file) return;
    const text = await file.text();
    try {
      JSON.parse(text);
      await api('/api/config/import', { method: 'POST', body: text });
      toast('配置已导入并生效', 'ok');
      renderConfigPage();
    } catch (err) {
      toast(`导入失败：${err.message}`, 'err');
    }
  });
}
