/**
 * 载荷元数据结构：
 * {
 *   id, category, name, vector, context,
 *   expectation: 'execute' | 'clobber' | 'cssFetch' | 'cssStyle' | 'block',
 *   detect: { canary?: string, expr?: string, style?: object },
 *   ref, description
 * }
 * - context: 注入位置，默认 'body'；还有 textarea/title/noscript/table/attr 等
 * - canary: 执行成功时应触发的标记（注入到 alert 调用里）
 * - expr: 在子帧 window 上求值的 clobber 判定表达式
 */

export const CATEGORIES = [
  { key: 'mxss', name: '突变型 XSS (mXSS)' },
  { key: 'clobbering', name: 'DOM Clobbering' },
  { key: 'css', name: 'CSS 注入' },
  { key: 'protocol', name: '协议混淆' },
  { key: 'classic', name: '基线回归' }
];
