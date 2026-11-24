/** 验证老接口 sanitize(html) 签名：浏览器全局与 ESM 两种引入行为一致 */
import { createHttpServer, listen } from '../../src/server/http.js';
import { launchChrome, CdpConnection, createPage, evalInPage } from '../../src/engine/chrome.js';

const server = createHttpServer();
const port = await listen(server, 0);
const chrome = await launchChrome();
const cdp = new CdpConnection(chrome.wsUrl);
await cdp.ready;
const page = await createPage(cdp, { url: 'about:blank' });

await page.send('Page.navigate', { url: `http://127.0.0.1:${port}/engine/harness.html` });
await new Promise(r => setTimeout(r, 1200));

const cases = [
  ['<img src=x onerror="alert(1)">', '事件属性'],
  ['<script>alert(1)</script>', '脚本标签'],
  ['<a href="javascript:alert(1)">x</a>', 'javascript 协议'],
  ['<p>Hello <strong>world</strong></p>', '正常富文本'],
  ['<svg onload="alert(1)"/>', 'SVG 外内容']
];

const out = await evalInPage(page, `(async () => {
  const core = await import('/src/sanitizer/index.js');
  const legacy = await import('/src/sanitizer/legacy.js');
  const vectors = ${JSON.stringify(cases.map(c => c[0]))};
  return vectors.map(v => ({
    input: v,
    // 老签名：只传一个 html 参数
    legacySignature: legacy.default(v),
    namedExport: legacy.sanitize(v),
    coreDefault: core.sanitize(v),
    globalFn: window.sanitize ? window.sanitize(v) : null
  }));
})()`, { awaitPromise: true });

let failures = 0;
for (let i = 0; i < out.length; i++) {
  const r = out[i];
  const consistent = r.legacySignature === r.namedExport &&
                     r.namedExport === r.coreDefault &&
                     r.coreDefault === r.globalFn;
  const noHandler = !/onerror|onload|<script|javascript:|<svg/i.test(r.legacySignature);
  console.log(`  ${consistent && noHandler ? '✓' : '✗'} ${cases[i][1]}: ${JSON.stringify(r.legacySignature)}`);
  if (!consistent) { failures++; console.log('    四种引入方式结果不一致:', JSON.stringify(r)); }
  if (!noHandler) failures++;
}

// 确认返回值是字符串（老签名约束），不是对象
const typeOk = typeof out[0].legacySignature === 'string';
console.log(`  ${typeOk ? '✓' : '✗'} sanitize(html) 返回字符串而非对象`);
if (!typeOk) failures++;

await cdp.close();
await chrome.close();
server.close();
console.log(failures === 0 ? '\n✓ 老接口兼容性全部通过\n' : `\n✗ ${failures} 项失败\n`);
process.exitCode = failures ? 1 : 0;
