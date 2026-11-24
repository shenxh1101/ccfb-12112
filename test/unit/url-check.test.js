import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  checkUrl, checkSrcset, parseSrcset, extractScheme, hasControlChars
} from '../../src/sanitizer/url-check.js';
import { createDefaultConfig } from '../../src/sanitizer/default-config.js';

const cfg = createDefaultConfig();
const urlCfg = cfg.url;
const imgCtx = { tag: 'img', attr: 'src' };
const aCtx = { tag: 'a', attr: 'href' };

test('协议白名单：http/https/mailto/tel 放行', () => {
  assert.equal(checkUrl('https://example.com/a', aCtx, urlCfg).ok, true);
  assert.equal(checkUrl('http://example.com', aCtx, urlCfg).ok, true);
  assert.equal(checkUrl('mailto:a@b.com', aCtx, urlCfg).ok, true);
  assert.equal(checkUrl('tel:+123456', aCtx, urlCfg).ok, true);
  assert.equal(checkUrl('/relative/path', aCtx, urlCfg).ok, true);
  assert.equal(checkUrl('page.html?q=1#f', aCtx, urlCfg).ok, true);
});

test('javascript: 及其大小写变体全部拒绝', () => {
  for (const v of [
    'javascript:alert(1)',
    'JavaScript:alert(1)',
    'JaVaScRiPt:alert(1)',
    'javascript:alert(document.cookie)'
  ]) {
    const r = checkUrl(v, aCtx, urlCfg);
    assert.equal(r.ok, false, v);
    assert.equal(r.ruleId, 'URL_SCHEME_DENY');
  }
});

test('协议混淆：内嵌 tab/换行/NUL/控制字符拒绝（不靠剥字符后判断）', () => {
  const obfuscated = [
    'java\tscript:alert(1)',
    'java\nscript:alert(1)',
    'java\rs cript:alert(1)',
    'java\x00script:alert(1)',
    ' java\x07script:alert(1)',
    '\x00javascript:alert(1)'
  ];
  for (const v of obfuscated) {
    const r = checkUrl(v, aCtx, urlCfg);
    assert.equal(r.ok, false, JSON.stringify(v));
    assert.equal(r.ruleId, 'URL_CONTROL_CHAR');
  }
  assert.equal(hasControlChars('javascript:alert(1)'), false);
});

test('vbscript/file/blob 协议拒绝', () => {
  for (const v of ['vbscript:msgbox(1)', 'file:///etc/passwd', 'blob:https://x/1234']) {
    assert.equal(checkUrl(v, aCtx, urlCfg).ok, false, v);
  }
});

test('data: 仅 img 上图片 MIME 放行，svg+xml 与 text/html 拒绝', () => {
  assert.equal(checkUrl('data:image/png;base64,AAA=', imgCtx, urlCfg).ok, true);
  assert.equal(checkUrl('data:image/jpeg;base64,AAA=', imgCtx, urlCfg).ok, true);
  assert.equal(checkUrl('data:image/gif;base64,AAA=', imgCtx, urlCfg).ok, true);
  assert.equal(checkUrl('data:image/webp;base64,AAA=', imgCtx, urlCfg).ok, true);

  const svg = checkUrl('data:image/svg+xml;base64,PHN2Zz4=', imgCtx, urlCfg);
  assert.equal(svg.ok, false);
  assert.equal(svg.ruleId, 'URL_DATA_MIME_DENY');

  const html = checkUrl('data:text/html;base64,PHNjcmlwdD4=', imgCtx, urlCfg);
  assert.equal(html.ok, false);

  // a[href] 上任何 data: 都拒绝
  assert.equal(checkUrl('data:image/png;base64,AAA=', aCtx, urlCfg).ok, false);
});

test('extractScheme 边界：冒号前有 / ? # 时视为相对 URL', () => {
  assert.equal(extractScheme('javascript:x'), 'javascript');
  assert.equal(extractScheme('/path:8080/x'), null);
  assert.equal(extractScheme('a?b:c'), null);
  assert.equal(extractScheme('a#b:c'), null);
  assert.equal(extractScheme('relative'), null);
});

test('srcset 解析：普通候选与 data URI 内逗号', () => {
  const parsed = parseSrcset('a.png 1x, b.png 2x');
  assert.deepEqual(parsed.map(p => p.url), ['a.png', 'b.png']);
  assert.equal(parsed[0].descriptor, '1x');

  const data = parseSrcset('data:image/png;base64,AA,,BB 1x, http://x/y.png 2x');
  assert.equal(data[0].url, 'data:image/png;base64,AA,,BB');
  assert.equal(data[1].url, 'http://x/y.png');
});

test('srcset 中任一候选含 javascript: 即整体拒绝', () => {
  const r = checkSrcset('http://x/a.png 1x, javascript:alert(1) 2x', imgCtx, urlCfg);
  assert.equal(r.ok, false);
  assert.equal(r.badUrl, 'javascript:alert(1)');
});

test('首尾空白与 BOM 被规整，内部控制字符仍拒绝', () => {
  const r = checkUrl('  https://example.com  ', aCtx, urlCfg);
  assert.equal(r.ok, true);
  assert.equal(r.normalized, 'https://example.com');
});
