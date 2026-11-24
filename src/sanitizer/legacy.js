/**
 * 老前端兼容层：保持 window.sanitize(html) 调用方式不变。
 * 浏览器中通过 <script type="module"> 引入本文件即可挂载全局；
 * Node/ESM 中直接 re-export 同名函数，行为与 src/sanitizer/index.js 完全一致。
 */

import { sanitize as coreSanitize, createDefaultConfig, createSanitizer } from './index.js';

function sanitize(html) {
  // 老签名：只接收 html 字符串，始终使用严格默认配置
  return coreSanitize(html);
}

if (typeof globalThis !== 'undefined') {
  globalThis.sanitize = sanitize;
  globalThis.createSanitizer = createSanitizer;
  globalThis.createDefaultSanitizerConfig = createDefaultConfig;
}

export { sanitize, createSanitizer, createDefaultConfig };
export default sanitize;
