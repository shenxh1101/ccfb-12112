/**
 * 自研显式序列化器：不使用 innerHTML 直出。
 * 输入是 walker 产出的安全节点树（白名单标签 + 已校验属性），
 * 统一转义规则，规避外内容命名空间与实体变异带来的 mXSS 面。
 * 运行环境需有 DOM（浏览器 / CDP harness），本身不做任何解析决策。
 */

const VOID_ELEMENTS = new Set([
  'area', 'base', 'br', 'col', 'embed', 'hr', 'img', 'input',
  'link', 'meta', 'param', 'source', 'track', 'wbr'
]);

/** 文本节点转义：& < >，并剔除 C0 控制字符（保留 \t \n \r） */
export function escapeText(text) {
  return String(text)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, '');
}

/** 属性值转义：& < > "，属性统一用双引号包裹；同样剔除控制字符 */
export function escapeAttr(value) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/"/g, '&quot;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, '');
}

/** 序列化一个元素节点（含后代） */
export function serializeElement(el) {
  const tag = el.tagName.toLowerCase();
  const parts = [`<${tag}`];
  for (const attr of Array.from(el.attributes)) {
    parts.push(` ${attr.name.toLowerCase()}="${escapeAttr(attr.value)}"`);
  }
  if (VOID_ELEMENTS.has(tag)) {
    parts.push('>');
    return parts.join('');
  }
  parts.push('>');
  for (const child of Array.from(el.childNodes)) {
    parts.push(serializeNode(child));
  }
  parts.push(`</${tag}>`);
  return parts.join('');
}

export function serializeNode(node) {
  switch (node.nodeType) {
    case 1: // Node.ELEMENT_NODE
      return serializeElement(node);
    case 3: // Node.TEXT_NODE
      return escapeText(node.data);
    default:
      // 注释、处理指令、DOCTYPE、CDATA 等一律不输出
      return '';
  }
}

/** 序列化 Document / DocumentFragment 的顶层子节点 */
export function serializeRoot(root) {
  const out = [];
  for (const child of Array.from(root.childNodes)) {
    out.push(serializeNode(child));
  }
  return out.join('');
}
