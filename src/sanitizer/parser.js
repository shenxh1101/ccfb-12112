/**
 * 解析封装：使用平台 DOMParser 按 text/html 解析。
 * 不手写 tokenizer——手写词法分析器本身就是 mXSS 的高发点；
 * 浏览器解析器对实体、外内容（SVG/Math）、foster parenting 的处理与最终渲染一致。
 * 运行环境需提供 DOMParser（浏览器 / CDP harness）。
 */

export function parseHtml(html, doc) {
  const owner = doc || (typeof document !== 'undefined' ? document : null);
  const DOMParserCtor = owner?.defaultView?.DOMParser || (typeof DOMParser !== 'undefined' ? DOMParser : null);
  if (!DOMParserCtor) {
    throw new Error('parseHtml 需要浏览器 DOM 环境（DOMParser），请在 harness/浏览器中调用');
  }
  const parser = new DOMParserCtor();
  return parser.parseFromString(String(html ?? ''), 'text/html');
}
