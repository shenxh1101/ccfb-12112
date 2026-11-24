/** DOM clobbering：污染 window 命名属性 / 元素集合，干扰业务脚本 */
export default [
  {
    id: 'clobber-01',
    category: 'clobbering',
    name: 'anchor name 覆盖 window 属性',
    vector: '<a name="clobbered1" href="https://attacker.invalid/">link</a>',
    context: 'body',
    expectation: 'clobber',
    detect: { expr: "window.clobbered1 instanceof HTMLElement" },
    ref: 'HTML named access on the Window object',
    description: '带 name 的 a 元素通过命名属性访问挂到 window，业务代码读取同名全局变量时拿到 DOM 节点而非预期对象。'
  },
  {
    id: 'clobber-02',
    category: 'clobbering',
    name: 'anchor id 覆盖 window 属性',
    vector: '<a id="clobbered2" href="https://attacker.invalid/">link</a>',
    context: 'body',
    expectation: 'clobber',
    detect: { expr: "window.clobbered2 instanceof HTMLElement" },
    ref: 'HTML named access (id 路径)',
    description: 'id 同样进入 window 命名属性，验证 id 收敛策略是否生效。'
  },
  {
    id: 'clobber-03',
    category: 'clobbering',
    name: 'form/input 两级 x.y clobber',
    vector: '<form id="clobbered3"><input name="constructor" value="evil"></form>',
    context: 'body',
    expectation: 'clobber',
    detect: { expr: "window.clobbered3 && window.clobbered3.constructor && window.clobbered3.constructor.value === 'evil'" },
    ref: 'HTMLFormElement.elements 命名访问',
    description: 'form 的命名控件成为 form 的属性，可伪造嵌套对象与 constructor，破坏 instanceof/默认值逻辑。'
  },
  {
    id: 'clobber-04',
    category: 'clobbering',
    name: 'form + output 复合 clobber',
    vector: '<form id="clobbered4"><output id="payload">clobbered</output></form>',
    context: 'body',
    expectation: 'clobber',
    detect: { expr: "window.clobbered4 && window.clobbered4.payload && window.clobbered4.payload.tagName === 'OUTPUT'" },
    ref: 'DOM clobbering: nested named access',
    description: 'output 等可命名元素形成两级命名访问，常用于覆盖 config.api 这类配置对象路径。'
  },
  {
    id: 'clobber-05',
    category: 'clobbering',
    name: 'img name 覆盖 document.body 类内置引用',
    vector: '<img name="body" src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+M8AAAMBAQDJ/pLvAAAAAElFTkSuQmCC">',
    context: 'body',
    expectation: 'clobber',
    detect: { expr: "document.body && document.images && document.images.namedItem('body') !== null" },
    ref: 'document.images / HTMLCollection namedItem',
    description: '具名 img 进入 document.images 等集合，老代码常以集合名裸访问，集合被污染后逻辑分支被操控。'
  },
  {
    id: 'clobber-06',
    category: 'clobbering',
    name: 'anchor href 的 toString clobber',
    vector: '<a id="clobbered6" href="javascript:alert(window.__canary)">x</a>',
    context: 'body',
    expectation: 'clobber',
    detect: { expr: "window.clobbered6 instanceof HTMLAnchorElement && window.clobbered6.toString().indexOf('javascript:') === 0" },
    ref: 'HTMLAnchorElement.toString 返回 href',
    description: 'anchor 的 toString() 返回 href 字符串；业务把对象转字符串做 URL 白名单时会拿到攻击者控制的 javascript: URL。'
  },
  {
    id: 'clobber-07',
    category: 'clobbering',
    name: 'object data clobber',
    vector: '<object id="clobbered7" data="https://attacker.invalid/x.json"></object>',
    context: 'body',
    expectation: 'clobber',
    detect: { expr: "window.clobbered7 instanceof HTMLObjectElement" },
    ref: 'HTMLObjectElement named access',
    description: 'object 元素同样进 window 命名属性，且 data 可指向外部资源，兼具 clobber 与外链能力。'
  },
  {
    id: 'clobber-08',
    category: 'clobbering',
    name: '覆盖业务配置对象名 config',
    vector: '<a id="config" href="https://attacker.invalid/cfg"></a>',
    context: 'body',
    expectation: 'clobber',
    detect: { expr: "window.config instanceof HTMLElement" },
    ref: '业务全局对象名 clobber',
    description: '直接覆盖净化器/编辑器常见的全局 config 名，验证敏感名 deny 列表。'
  },
  {
    id: 'clobber-09',
    category: 'clobbering',
    name: '同名元素集合 clobber（HTMLCollection）',
    vector: '<a name="clobbered9"></a><a name="clobbered9"></a>',
    context: 'body',
    expectation: 'clobber',
    detect: { expr: "window.clobbered9 && window.clobbered9.length === 2" },
    ref: 'duplicate name → HTMLCollection',
    description: '重名时 window 属性变成 HTMLCollection，业务若按单对象处理会取到集合，行为异常可被利用。'
  }
];
