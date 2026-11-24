/**
 * 严格 CSS 白名单守卫（纯逻辑）。仅在配置开启 css.allowStyleAttr / allowStyleTag 时启用；
 * 默认配置下两者都关闭，模块不会被调用。
 *
 * 手写声明式解析，不依赖浏览器 CSSOM（CSSOM 会自动丢弃/改写非法声明，
 * 无法据此还原攻击者的原始意图）。
 */

import { hasControlChars } from './url-check.js';

/**
 * 解析并过滤 style 属性值（声明列表，如 "color:red; background:url(x)"）。
 * @returns {{ok:boolean, css?:string, dropped:Array<{decl:string, ruleId:string, reason:string}>}}
 */
export function guardStyleAttribute(rawValue, cssConfig) {
  const dropped = [];
  if (hasControlChars(rawValue)) {
    return { ok: false, dropped: [{ decl: rawValue, ruleId: 'CSS_CONTROL_CHAR', reason: 'style 值含控制字符' }] };
  }
  const kept = [];
  for (const part of splitDeclarations(rawValue)) {
    const r = checkDeclaration(part, cssConfig);
    if (r.ok) kept.push(r.normalized);
    else dropped.push({ decl: part, ruleId: r.ruleId, reason: r.reason });
  }
  return { ok: kept.length > 0, css: kept.join('; '), dropped };
}

/**
 * 校验 <style> 标签文本：只允许选择器 + 白名单声明构成的简单规则集，
 * 拒绝 @ 规则（@import/@font-face/@media 中的外链等）。
 * @returns {{ok:boolean, css?:string, dropped:Array}}
 */
export function guardStyleTag(rawText, cssConfig) {
  const dropped = [];
  if (hasControlChars(rawText)) {
    return { ok: false, dropped: [{ decl: rawText, ruleId: 'CSS_CONTROL_CHAR', reason: 'style 文本含控制字符' }] };
  }
  const rules = splitRules(rawText);
  const kept = [];
  for (const rule of rules) {
    const check = checkRule(rule, cssConfig);
    if (check.ok) kept.push(check.normalized);
    else dropped.push({ decl: rule.preview, ruleId: check.ruleId, reason: check.reason });
  }
  return { ok: kept.length > 0, css: kept.join('\n'), dropped };
}

/** 按分号切声明（引号内分号做简单保护） */
function splitDeclarations(text) {
  const out = [];
  let buf = '';
  let quote = null;
  for (const ch of text) {
    if (quote) {
      buf += ch;
      if (ch === quote) quote = null;
      continue;
    }
    if (ch === '"' || ch === "'") { quote = ch; buf += ch; continue; }
    if (ch === ';') { out.push(buf.trim()); buf = ''; continue; }
    buf += ch;
  }
  if (buf.trim()) out.push(buf.trim());
  return out.filter(Boolean);
}

function checkDeclaration(decl, cssConfig) {
  const colon = decl.indexOf(':');
  if (colon === -1) {
    return { ok: false, ruleId: 'CSS_MALFORMED', reason: '声明缺少冒号' };
  }
  const property = decl.slice(0, colon).trim().toLowerCase();
  const value = decl.slice(colon + 1).trim().toLowerCase();

  if (!/^[a-z-]+$/.test(property)) {
    return { ok: false, ruleId: 'CSS_PROPERTY_INVALID', reason: `非法属性名: ${property}` };
  }
  if (property.startsWith('--')) {
    return { ok: false, ruleId: 'CSS_CUSTOM_PROP_DENY', reason: 'CSS 自定义属性(--*)默认拒绝' };
  }
  // 危险值特征优先于属性白名单：即使属性合法，url()/expression 等也必须拦下
  for (const pattern of cssConfig.strict.forbiddenValuePatterns) {
    if (value.includes(pattern)) {
      return { ok: false, ruleId: 'CSS_VALUE_DENY', reason: `值命中危险特征 "${pattern}"` };
    }
  }
  if (!cssConfig.strict.allowedProperties.includes(property)) {
    return { ok: false, ruleId: 'CSS_PROPERTY_DENY', reason: `属性 "${property}" 不在 strict 白名单` };
  }
  if (/[{}<>]|\\[0-9a-f]|\\\n/.test(value)) {
    return { ok: false, ruleId: 'CSS_VALUE_DENY', reason: '值含转义/结构字符，疑似突破声明边界' };
  }
  return { ok: true, normalized: `${property}: ${value}` };
}

/** 极简规则集切分：按顶层花括号切 selector { decls }，@ 规则单独标记 */
function splitRules(text) {
  const rules = [];
  let i = 0;
  while (i < text.length) {
    while (/\s/.test(text[i])) i++;
    const start = i;
    while (i < text.length && text[i] !== '{') i++;
    const selector = text.slice(start, i).trim();
    if (i >= text.length) {
      if (selector) rules.push({ selector, body: '', preview: selector.slice(0, 60) });
      break;
    }
    const bodyStart = i + 1;
    i = bodyStart;
    while (i < text.length && text[i] !== '}') i++;
    const body = text.slice(bodyStart, i);
    if (text[i] === '}') i++;
    rules.push({ selector, body, preview: `${selector.slice(0, 40)} {…}` });
  }
  return rules;
}

function checkRule(rule, cssConfig) {
  if (rule.selector.startsWith('@')) {
    return { ok: false, ruleId: 'CSS_AT_RULE_DENY', reason: `@ 规则默认拒绝: ${rule.selector.slice(0, 30)}` };
  }
  if (!rule.body) {
    return { ok: false, ruleId: 'CSS_RULE_EMPTY', reason: '规则缺少声明体' };
  }
  const bodyResult = guardStyleAttribute(rule.body, cssConfig);
  if (!bodyResult.ok) {
    return { ok: false, ruleId: 'CSS_RULE_BODY_DENY', reason: '规则体内声明全部被拒' };
  }
  const safeSelector = rule.selector.replace(/[<>]/g, '');
  return { ok: true, normalized: `${safeSelector} { ${bodyResult.css}; }` };
}
