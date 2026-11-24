/**
 * 白名单树遍历器：在已解析的 DOM 上做净化决策，并记录完整决策 trace。
 * 每个放行/拒绝动作都带稳定 ruleId，供扫描结果页与 remediation 引擎使用。
 *
 * 处理模型：
 *  - 标签在白名单 → 深拷贝后按属性白名单过滤；
 *  - 标签不在白名单且在 dropWithContent → 整棵子树丢弃；
 *  - 标签不在白名单其余情况 → 去标签、保留子节点（unwrap），继续递归；
 *  - 非 HTML 命名空间（SVG/MathML 外内容）一律拒绝，这是历史绕过点。
 */

import { checkUrl, checkSrcset, hasControlChars } from './url-check.js';
import { checkId } from './clobber-guard.js';
import { guardStyleAttribute } from './css-guard.js';

const HTML_NAMESPACE = 'http://www.w3.org/1999/xhtml';

export function walkDocument(parsedDoc, config, ownerDocument) {
  const trace = [];
  const stats = {
    tagsAllowed: 0,
    tagsDropped: 0,
    tagsUnwrapped: 0,
    attrsAllowed: 0,
    attrsDropped: 0
  };
  const output = ownerDocument.createDocumentFragment();
  for (const child of Array.from(parsedDoc.body.childNodes)) {
    processNode(child, output, config, trace, stats, ownerDocument);
  }
  return { fragment: output, trace, stats };
}

function tracePush(trace, ruleId, action, target, reason) {
  trace.push({ ruleId, action, target, reason });
}

function processNode(node, parent, config, trace, stats, doc) {
  if (node.nodeType === 3) { // 文本节点直接保留（序列化器统一转义）
    parent.appendChild(node.cloneNode(true));
    return;
  }
  if (node.nodeType !== 1) { // 注释/CDATA/处理指令等不输出
    tracePush(trace, 'NODE_NON_ELEMENT_DROP', 'drop', `nodeType=${node.nodeType}`, '非元素/文本节点不输出');
    return;
  }

  const tag = node.tagName.toLowerCase();

  // 外内容命名空间（SVG/MathML）——历史绕过点，默认无差别拒绝
  if (node.namespaceURI && node.namespaceURI !== HTML_NAMESPACE) {
    parent.appendChild(node.cloneNode(true));
    tracePush(trace, 'TAG_FOREIGN_DROP', 'drop', `<${tag}>`, `非 HTML 命名空间 ${node.namespaceURI}（SVG/MathML 外内容可承载变异与脚本），整棵子树拒绝`);
    stats.tagsDropped++;
    stripElement(parent.lastChild, trace, stats);
    return;
  }

  const allowed = config.tags.allowed.includes(tag);
  if (!allowed) {
    if (config.tags.dropWithContent.includes(tag)) {
      tracePush(trace, 'TAG_DROP', 'drop', `<${tag}>`, '标签在 dropWithContent 清单，整棵子树移除');
      stats.tagsDropped++;
      return;
    }
    tracePush(trace, 'TAG_UNWRAP', 'unwrap', `<${tag}>`, '标签不在白名单，移除标签但继续处理子节点');
    stats.tagsUnwrapped++;
    for (const child of Array.from(node.childNodes)) {
      processNode(child, parent, config, trace, stats, doc);
    }
    return;
  }

  // 白名单标签：深拷贝后过滤属性，再递归子节点
  const el = node.cloneNode(false);
  parent.appendChild(el);
  stats.tagsAllowed++;
  tracePush(trace, 'TAG_ALLOW', 'allow', `<${tag}>`, '标签命中白名单');
  filterAttributes(el, tag, config, trace, stats);

  for (const child of Array.from(node.childNodes)) {
    processNode(child, el, config, trace, stats, doc);
  }
}

/** 深拷贝进来的外内容元素整体清空（保留无内容壳会被序列化器按未知元素输出，直接清空更稳） */
function stripElement(el, trace, stats) {
  while (el.firstChild) el.removeChild(el.firstChild);
  for (const attr of Array.from(el.attributes)) {
    el.removeAttribute(attr.name);
    stats.attrsDropped++;
  }
  tracePush(trace, 'FOREIGN_ATTR_PURGE', 'drop', el.tagName.toLowerCase(), '外内容元素属性全部清除');
  // 最终把空壳也移除
  el.parentNode?.removeChild(el);
}

function filterAttributes(el, tag, config, trace, stats) {
  const globalAttrs = config.attrs.global;
  const tagAttrs = config.attrs.perTag[tag] || [];
  const urlAttrs = config.url.urlAttrs[tag] || [];

  for (const attr of Array.from(el.attributes)) {
    const name = attr.name.toLowerCase();
    const value = attr.value;
    const target = `${tag}[${name}]`;

    // 0. 控制字符（混淆属性名/值的经典手法）
    if (config.attrs.rejectControlChars && (hasControlChars(name) || hasControlChars(value))) {
      el.removeAttribute(attr.name);
      stats.attrsDropped++;
      tracePush(trace, 'ATTR_CONTROL_CHAR_DROP', 'drop', target, '属性名或值含 ASCII 控制字符/NUL');
      continue;
    }

    // 1. 事件处理属性：任何 on* 一律拒绝
    if (name.startsWith('on')) {
      el.removeAttribute(attr.name);
      stats.attrsDropped++;
      tracePush(trace, 'ATTR_DROP_EVENT', 'drop', target, '事件处理属性(on*)默认全拒');
      continue;
    }

    // 2. name 属性全局丢弃（DOM clobbering 主入口）
    if (name === 'name' && config.attrs.dropNameAttr) {
      el.removeAttribute(attr.name);
      stats.attrsDropped++;
      tracePush(trace, 'ATTR_DROP_NAME', 'drop', target, 'name 属性全局丢弃，阻断 DOM clobbering');
      continue;
    }

    // 3. id 收敛
    if (name === 'id') {
      const r = checkId(value, config.attrs.id);
      if (!r.ok) {
        el.removeAttribute(attr.name);
        stats.attrsDropped++;
        tracePush(trace, r.ruleId, 'drop', target, r.reason);
        continue;
      }
      stats.attrsAllowed++;
      tracePush(trace, 'ATTR_ALLOW_ID', 'allow', target, 'id 通过白名单模式与敏感名检查');
      continue;
    }

    // 4. style 属性（默认关闭）
    if (name === 'style') {
      if (!config.css.allowStyleAttr) {
        el.removeAttribute(attr.name);
        stats.attrsDropped++;
        tracePush(trace, 'ATTR_DROP_STYLE', 'drop', target, 'style 属性默认关闭（历史绕过点），可在配置中启用 strict-css 预设');
        continue;
      }
      const r = guardStyleAttribute(value, config.css);
      if (!r.ok) {
        el.removeAttribute(attr.name);
        stats.attrsDropped++;
        tracePush(trace, 'CSS_ATTR_DROP_ALL', 'drop', target, `style 声明全部被拒: ${r.dropped.map(d => d.ruleId).join(',')}`);
        continue;
      }
      el.setAttribute('style', r.css);
      stats.attrsAllowed++;
      tracePush(trace, 'CSS_ATTR_FILTERED', 'allow', target, `strict-css 保留 ${r.css.length} 字符，丢弃 ${r.dropped.length} 条声明`);
      for (const d of r.dropped) tracePush(trace, d.ruleId, 'drop', `${target}: ${d.decl.slice(0, 40)}`, d.reason);
      continue;
    }

    // 5. 属性白名单（通用 + 按标签）
    const inAllowList = globalAttrs.includes(name) || tagAttrs.includes(name);
    if (!inAllowList) {
      el.removeAttribute(attr.name);
      stats.attrsDropped++;
      tracePush(trace, 'ATTR_DROP_NOT_ALLOWED', 'drop', target, `属性不在 ${tag} 的白名单内`);
      continue;
    }

    // 6. URL 类属性协议校验
    if (urlAttrs.includes(name)) {
      if (name === 'srcset') {
        const r = checkSrcset(value, { tag, attr: name }, config.url);
        if (!r.ok) {
          el.removeAttribute(attr.name);
          stats.attrsDropped++;
          tracePush(trace, r.ruleId, 'drop', target, r.detail || `srcset 中存在非法候选: ${r.badUrl || ''}`);
          continue;
        }
      } else {
        const r = checkUrl(value, { tag, attr: name }, config.url);
        if (!r.ok) {
          el.removeAttribute(attr.name);
          stats.attrsDropped++;
          tracePush(trace, r.ruleId, 'drop', target, r.detail || `URL 协议校验失败: ${r.ruleId}`);
          continue;
        }
        if (r.normalized !== value) el.setAttribute(name, r.normalized);
      }
    }

    stats.attrsAllowed++;
    tracePush(trace, 'ATTR_ALLOW', 'allow', target, '属性命中白名单且通过校验');
  }

  // 7. target=_blank 强制 noopener，防 reverse tabnabbing
  if (config.url.enforceNoopener && tag === 'a' && el.getAttribute('target') === '_blank') {
    const rel = new Set((el.getAttribute('rel') || '').split(/\s+/).filter(Boolean));
    rel.add('noopener');
    rel.add('noreferrer');
    el.setAttribute('rel', [...rel].join(' '));
    tracePush(trace, 'URL_NOOPENER_ENFORCE', 'modify', 'a[rel]', 'target=_blank 强制补充 rel=noopener noreferrer');
  }
}
