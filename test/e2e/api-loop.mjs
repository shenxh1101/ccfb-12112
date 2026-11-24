/** 通过 HTTP API 验证：放宽配置 → 扫出绕过 → 取建议 → 一键应用 → 重扫翻转 → 恢复默认 */
const BASE = 'http://127.0.0.1:8127';

async function call(path, options = {}) {
  const opts = { headers: { 'Content-Type': 'application/json' }, ...options };
  if (options.body) opts.body = JSON.stringify(options.body);
  const res = await fetch(BASE + path, opts);
  return res.json();
}

let failures = 0;
const check = (cond, msg) => {
  console.log(cond ? `  ✓ ${msg}` : `  ✗ ${msg}`);
  if (!cond) failures++;
};

// 1. 取当前配置并放宽协议
const cfg = await call('/api/config');
cfg.url.allowedProtocols.push('javascript:');
await call('/api/config', { method: 'PUT', body: cfg });

// 2. 扫协议类
const scan = await call('/api/scan', { method: 'POST', body: { category: 'protocol' } });
console.log(`\n放宽后扫描: ${scan.bypassed} 绕过 / ${scan.blocked} 挡住`);
check(scan.bypassed > 0, '放宽 javascript: 后能检测到绕过');
const bypassEvent = scan.results.find(r => r.status === 'bypass');
check(bypassEvent?.evidence?.events?.[0]?.detail === bypassEvent.payloadId,
  `canary 事件带出席次 id（${bypassEvent?.evidence?.events?.[0]?.detail}）`);

// 3. 取修复建议
const { advice } = await call(`/api/remediation/${scan.id}`);
check(advice.some(a => a.id === 'tighten-protocols'), '生成协议收敛建议');
const target = advice.find(a => a.id === 'tighten-protocols');

// 4. 一键应用并重扫
const applied = await call('/api/remediation/apply', {
  method: 'POST',
  body: { scanId: scan.id, adviceId: target.id, rescan: true }
});
check(!applied.config.url.allowedProtocols.includes('javascript:'), '应用后 javascript: 已移出协议白名单');
check(applied.rescan.bypassed === 0, `重扫绕过数归零（实际 ${applied.rescan.bypassed}）`);
console.log(`\n应用修复后重扫: ${applied.rescan.blocked} 挡住 / ${applied.rescan.bypassed} 绕过`);

// 5. 导入导出往返
const exported = JSON.parse(await (await fetch(`${BASE}/api/config/export`)).text());
check(!!exported.config && exported.tool === 'xss-sanitizer-range', '导出包含 config 段与工具标识');
// import 端点接收原始 JSON 文本（不能再 stringify 一次）
const importRes = await fetch(`${BASE}/api/config/import`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(exported)
});
const reimported = await importRes.json();
check(reimported.schemaVersion === exported.config.schemaVersion, '导入后 schemaVersion 一致');

// 6. 恢复默认
await call('/api/config/reset', { method: 'POST' });
const reset = await call('/api/config');
check(reset.css.allowStyleAttr === false && reset.attrs.id.enabled === false, '恢复严格默认（style 关、id fail-closed）');

console.log(failures === 0 ? '\n✓ API 修复闭环全部通过\n' : `\n✗ ${failures} 项失败\n`);
process.exitCode = failures ? 1 : 0;
