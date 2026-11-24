/** 协议混淆：scheme 编码/控制字符/实体/data/blob 等 */
export default [
  {
    id: 'proto-01',
    category: 'protocol',
    name: '标准 javascript: 协议',
    vector: '<a href="javascript:alert(window.__canary)">click</a>',
    context: 'body',
    expectation: 'execute',
    detect: { canary: 'proto-01', click: 'a' },
    ref: 'javascript: URL scheme',
    description: '基线：点击后在当前文档执行脚本，扫描器会程序化 click 所有 a[href]。'
  },
  {
    id: 'proto-02',
    category: 'protocol',
    name: '大小写混排 JavaScript:',
    vector: '<a href="JaVaScRiPt:alert(window.__canary)">click</a>',
    context: 'body',
    expectation: 'execute',
    detect: { canary: 'proto-02', click: 'a' },
    ref: 'scheme 大小写不敏感',
    description: 'scheme 是 ASCII 大小写不敏感的，黑名单精确匹配小写会被绕过。'
  },
  {
    id: 'proto-03',
    category: 'protocol',
    name: '内嵌 tab 的 java\\tscript:',
    vector: '<a href="java\tscript:alert(window.__canary)">click</a>',
    context: 'body',
    expectation: 'execute',
    detect: { canary: 'proto-03', click: 'a' },
    ref: 'scheme 中的控制字符剥离差异',
    description: '部分浏览器/旧库会剥离 tab 后再解析 scheme；净化器选择含控制字符即拒绝。'
  },
  {
    id: 'proto-04',
    category: 'protocol',
    name: '内嵌换行 java\\nscript:',
    vector: '<a href="java\nscript:alert(window.__canary)">click</a>',
    context: 'body',
    expectation: 'execute',
    detect: { canary: 'proto-04', click: 'a' },
    ref: 'scheme 中的 LF',
    description: '换行混淆，字符串包含判断 "javascript:" 失效。'
  },
  {
    id: 'proto-05',
    category: 'protocol',
    name: 'NUL 截断 java\\0script:',
    vector: '<a href="java\x00script:alert(window.__canary)">click</a>',
    context: 'body',
    expectation: 'execute',
    detect: { canary: 'proto-05', click: 'a' },
    ref: 'NUL byte scheme obfuscation',
    description: 'NUL 在 C 字符串截断语义下曾导致大量黑名单绕过。'
  },
  {
    id: 'proto-06',
    category: 'protocol',
    name: 'HTML 实体编码 &colon;',
    vector: '<a href="javascript&colon;alert(window.__canary)">click</a>',
    context: 'body',
    expectation: 'execute',
    detect: { canary: 'proto-06', click: 'a' },
    ref: 'HTML attribute entity decoding',
    description: 'DOMParser 在属性值中解码实体，净化器必须在解码后的真实值上做协议判断。'
  },
  {
    id: 'proto-07',
    category: 'protocol',
    name: '数字实体编码冒号',
    vector: '<a href="javascript&#58;alert(window.__canary)">click</a>',
    context: 'body',
    expectation: 'execute',
    detect: { canary: 'proto-07', click: 'a' },
    ref: 'numeric character reference',
    description: '&#58; 与 &#x3a; 都是冒号，验证实体解码发生在校验之前。'
  },
  {
    id: 'proto-08',
    category: 'protocol',
    name: '前导空白混淆',
    vector: '<a href="  javascript:alert(window.__canary)">click</a>',
    context: 'body',
    expectation: 'execute',
    detect: { canary: 'proto-08', click: 'a' },
    ref: 'leading whitespace before scheme',
    description: '空白被 URL 规整后 scheme 生效；校验器 trim 后仍需识别真实 scheme。'
  },
  {
    id: 'proto-09',
    category: 'protocol',
    name: 'data:text/html 脚本文档',
    vector: '<a href="data:text/html,<script>alert(window.__canary)</script>">click</a>',
    context: 'body',
    expectation: 'execute',
    detect: { canary: 'proto-09', click: 'a' },
    ref: 'data: URL HTML document',
    description: 'data: 导航会创建可执行脚本的文档；a[href] 上任何 data: 都应拒绝。'
  },
  {
    id: 'proto-10',
    category: 'protocol',
    name: 'data:image/svg+xml 带脚本',
    vector: '<img src="data:image/svg+xml,<svg xmlns=\'http://www.w3.org/2000/svg\' onload=\'alert(window.__canary)\'/>">',
    context: 'body',
    expectation: 'execute',
    detect: { canary: 'proto-10' },
    ref: 'SVG data URI script execution',
    description: 'SVG 是 XML 文档可携带脚本事件；data: 图片 MIME 白名单明确排除 svg+xml。'
  },
  {
    id: 'proto-11',
    category: 'protocol',
    name: 'vbscript: 协议',
    vector: '<a href="vbscript:msgbox(window.__canary)">click</a>',
    context: 'body',
    expectation: 'execute',
    detect: { canary: 'proto-11', click: 'a' },
    ref: 'vbscript scheme (legacy IE/webview)',
    description: '老旧 IE/嵌入式 webview 支持，白名单制天然拒绝，但保留用例回归。'
  },
  {
    id: 'proto-12',
    category: 'protocol',
    name: 'srcset 中隐藏 javascript: 候选',
    vector: '<img srcset="/safe.png 1x, javascript:alert(window.__canary) 2x">',
    context: 'body',
    expectation: 'execute',
    detect: { canary: 'proto-12' },
    ref: 'srcset candidate parsing',
    description: 'srcset 是多候选语法，只校验第一个 URL 的过滤器会漏掉后面的 javascript: 候选。'
  }
];
