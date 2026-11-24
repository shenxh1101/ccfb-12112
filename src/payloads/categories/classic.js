/** 基线回归：经典脚本执行向量，确保检测能力本身有效 */
export default [
  {
    id: 'classic-01',
    category: 'classic',
    name: '内联 <script>',
    vector: '<script>alert(window.__canary)</script>',
    context: 'body',
    expectation: 'execute',
    detect: { canary: 'classic-01' },
    ref: '最基础的脚本向量',
    description: '回归基线：脚本标签必须整体丢弃。'
  },
  {
    id: 'classic-02',
    category: 'classic',
    name: 'img onerror 事件',
    vector: '<img src=x onerror="alert(window.__canary)">',
    context: 'body',
    expectation: 'execute',
    detect: { canary: 'classic-02' },
    ref: '事件处理属性',
    description: '回归基线：on* 属性全拒。'
  },
  {
    id: 'classic-03',
    category: 'classic',
    name: 'SVG onload 事件',
    vector: '<svg onload="alert(window.__canary)"></svg>',
    context: 'body',
    expectation: 'execute',
    detect: { canary: 'classic-03' },
    ref: 'SVG 动画/加载事件',
    description: 'SVG 元素的 onload 不需要子资源即触发，历史高频绕过。'
  },
  {
    id: 'classic-04',
    category: 'classic',
    name: 'object 元素',
    vector: '<object data="javascript:alert(window.__canary)"></object>',
    context: 'body',
    expectation: 'execute',
    detect: { canary: 'classic-04' },
    ref: 'HTMLObjectElement',
    description: 'object 可嵌入各类活动内容，默认标签白名单不含 object。'
  },
  {
    id: 'classic-05',
    category: 'classic',
    name: 'embed 元素',
    vector: '<embed src="javascript:alert(window.__canary)">',
    context: 'body',
    expectation: 'execute',
    detect: { canary: 'classic-05' },
    ref: 'HTMLEmbedElement',
    description: 'embed 为 void 元素且语义接近 object，默认拒绝。'
  },
  {
    id: 'classic-06',
    category: 'classic',
    name: 'meta refresh 跳转',
    vector: '<meta http-equiv="refresh" content="0;url=javascript:alert(window.__canary)">',
    context: 'head',
    expectation: 'execute',
    detect: { canary: 'classic-06' },
    ref: 'meta refresh javascript: URL',
    description: 'meta 在 head 中触发导航，meta 标签整体在 dropWithContent 清单。'
  },
  {
    id: 'classic-07',
    category: 'classic',
    name: 'base 标签劫持相对 URL',
    vector: '<base href="//xss-canary-classic-07.invalid/">',
    context: 'head',
    expectation: 'cssFetch',
    detect: { canary: 'xss-canary-classic-07.invalid' },
    ref: 'base target/href hijack',
    description: 'base 改写页面所有相对 URL 的解析基址，可把后续资源/表单导向攻击者主机。'
  },
  {
    id: 'classic-08',
    category: 'classic',
    name: 'setTimeout 字符串形式',
    vector: '<img src=x onerror="setTimeout(String.fromCharCode(97,108,101,114,116,40,119,105,110,100,111,119,46,95,95,99,97,110,97,114,121,41),0)">',
    context: 'body',
    expectation: 'execute',
    detect: { canary: 'classic-08' },
    ref: 'setTimeout 字符串求值',
    description: '事件里嵌套字符串求值与 charCode 混淆，验证异步执行检测窗口能覆盖定时器。'
  },
  {
    id: 'classic-09',
    category: 'classic',
    name: 'body onload 事件',
    vector: '<body onload="alert(window.__canary)">',
    context: 'body',
    expectation: 'execute',
    detect: { canary: 'classic-09' },
    ref: 'body event handler',
    description: 'body 元素事件属性，验证白名单标签之外的事件属性同样被拒（body 本身也不在白名单）。'
  }
];
