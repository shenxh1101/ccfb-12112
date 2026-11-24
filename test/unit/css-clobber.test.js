import { test } from 'node:test';
import assert from 'node:assert/strict';
import { guardStyleAttribute, guardStyleTag } from '../../src/sanitizer/css-guard.js';
import { checkId } from '../../src/sanitizer/clobber-guard.js';
import { createDefaultConfig } from '../../src/sanitizer/default-config.js';
import { escapeText, escapeAttr } from '../../src/sanitizer/serializer.js';

const cssConfig = createDefaultConfig().css;

test('strict-css：白名单属性保留，未知属性拒绝', () => {
  const r = guardStyleAttribute('color: red; font-weight: bold', cssConfig);
  assert.equal(r.ok, true);
  assert.match(r.css, /color: red/);
  assert.match(r.css, /font-weight: bold/);

  const bad = guardStyleAttribute('position: fixed; top: 0', cssConfig);
  assert.equal(bad.ok, false);
  assert.equal(bad.dropped[0].ruleId, 'CSS_PROPERTY_DENY');
});

test('strict-css：url()/expression/@import/javascript: 全部命中危险特征', () => {
  for (const v of [
    'background: url(//xss-canary.invalid/x)',
    'width: expression(alert(1))',
    'color: red; background-image: url(javascript:alert(1))',
    'behavior: url(x.htc)'
  ]) {
    const r = guardStyleAttribute(v, cssConfig);
    assert.equal(r.dropped.some(d => d.ruleId === 'CSS_VALUE_DENY'), true, v);
  }
});

test('strict-css：自定义属性与控制字符拒绝', () => {
  const custom = guardStyleAttribute('--evil: red', cssConfig);
  assert.equal(custom.dropped[0].ruleId, 'CSS_CUSTOM_PROP_DENY');
  const ctrl = guardStyleAttribute('color:\x00red', cssConfig);
  assert.equal(ctrl.ok, false);
  assert.equal(ctrl.dropped[0].ruleId, 'CSS_CONTROL_CHAR');
});

test('style 标签：@import/@font-face 等 @ 规则拒绝，普通规则按声明白名单过滤', () => {
  const atRule = guardStyleTag('@import url(//xss-canary.invalid/m);', cssConfig);
  assert.equal(atRule.ok, false);
  assert.equal(atRule.dropped[0].ruleId, 'CSS_AT_RULE_DENY');

  const fontFace = guardStyleTag('@font-face { font-family: x; src: url(//x/c.woff); }', cssConfig);
  assert.equal(fontFace.ok, false);

  const normal = guardStyleTag('p { color: red; position: fixed; }', cssConfig);
  assert.equal(normal.ok, true);
  assert.match(normal.css, /color: red/);
  assert.doesNotMatch(normal.css, /position/);
});

test('clobber 守卫：默认 fail-closed 拒绝所有 id；启用后走正则与敏感名 deny', () => {
  const defaultIdCfg = createDefaultConfig().attrs.id;
  // 默认关闭：任何 id 都拒绝
  assert.equal(checkId('post-12', defaultIdCfg).ok, false);
  assert.equal(checkId('post-12', defaultIdCfg).ruleId, 'CLOBBER_ID_DISABLED');

  // 显式启用后才进入模式 + deny 校验
  const enabled = { ...defaultIdCfg, enabled: true };
  assert.equal(checkId('post-12', enabled).ok, true);
  assert.equal(checkId('x', enabled).ok, false); // 单字符 + 命中 deny 名 x
  assert.equal(checkId('config', enabled).ok, false);
  assert.equal(checkId('sanitize', enabled).ok, false);
  assert.equal(checkId('document', enabled).ok, false);
  assert.equal(checkId('a b', enabled).ok, false); // 不符合正则
  assert.equal(checkId('1abc', enabled).ok, false); // 数字开头
  assert.equal(checkId('good-id_1', enabled).ok, true);
});

test('序列化转义：文本与属性', () => {
  assert.equal(escapeText('<a> & "x"'), '&lt;a&gt; &amp; "x"');
  assert.equal(escapeAttr('"x" & <y>'), '&quot;x&quot; &amp; &lt;y&gt;');
  assert.equal(escapeText('a\x00b'), 'ab');
});
