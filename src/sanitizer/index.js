/**
 * 净化器公共入口。
 *
 * 兼容约束：老前端调用 sanitize(html) 的签名不能改。
 * 因此第二参数为可选对象 { config, trace }，不传时使用严格默认配置。
 */

import { createDefaultConfig } from './default-config.js';
import { parseHtml } from './parser.js';
import { walkDocument } from './walker.js';
import { serializeRoot } from './serializer.js';

/** 工厂：返回绑定配置的净化器实例 */
export function createSanitizer(config) {
  const resolved = config || createDefaultConfig();
  return {
    config: resolved,
    sanitize(html, options = {}) {
      return sanitize(html, { ...options, config: resolved });
    }
  };
}

/**
 * 净化 HTML。
 * @param {string} html 原始输入
 * @param {object} [options]
 * @param {object} [options.config] 自定义配置，默认严格配置
 * @param {boolean} [options.trace] 是否返回决策 trace（扫描时使用）
 * @returns {string|{html:string, trace:Array, stats:object}}
 *   默认返回净化后的 HTML 字符串（老签名行为不变）；
 *   options.trace=true 时返回 { html, trace, stats }。
 */
export function sanitize(html, options = {}) {
  const config = options.config || createDefaultConfig();
  const wantTrace = options.trace === true;
  const parsed = parseHtml(html);
  const { fragment, trace, stats } = walkDocument(parsed, config, parsed);
  const out = serializeRoot(fragment);
  if (wantTrace) return { html: out, trace, stats };
  return out;
}

export { createDefaultConfig } from './default-config.js';
export { withStrictCss } from './default-config.js';
export { parseHtml } from './parser.js';
export { serializeRoot, escapeText, escapeAttr } from './serializer.js';
