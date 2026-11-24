/**
 * 严格默认配置与预设。
 * 设计原则：白名单制（不在清单内即拒绝），默认配置下载荷库全部攻击用例必须被挡住。
 */

export const CONFIG_SCHEMA_VERSION = 1;

/** 仅排版用途的 HTML 标签白名单；script/style/svg/math/form/iframe 等一律不在内 */
export const DEFAULT_ALLOWED_TAGS = [
  'a', 'abbr', 'b', 'blockquote', 'br', 'caption', 'cite', 'code', 'col',
  'colgroup', 'dd', 'del', 'div', 'dl', 'dt', 'em', 'figcaption', 'figure',
  'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'hr', 'i', 'img', 'ins', 'kbd', 'li',
  'mark', 'ol', 'p', 'pre', 'q', 's', 'samp', 'small', 'span', 'strong',
  'sub', 'sup', 'table', 'tbody', 'td', 'tfoot', 'th', 'thead', 'tr', 'u',
  'ul', 'var'
];

/** 全局允许的通用属性（任何白名单标签上均可出现） */
export const DEFAULT_GLOBAL_ATTRS = ['dir', 'lang', 'title'];

/** 按标签限定的属性白名单 */
export const DEFAULT_TAG_ATTRS = {
  a: ['href', 'rel', 'target'],
  blockquote: ['cite'],
  col: ['span'],
  colgroup: ['span'],
  img: ['src', 'alt', 'width', 'height'],
  ol: ['start', 'reversed', 'type'],
  q: ['cite'],
  table: ['border'],
  td: ['colspan', 'rowspan'],
  th: ['colspan', 'rowspan', 'scope'],
  ul: ['type']
};

/** 携带 URL、必须做协议校验的属性（按标签） */
export const DEFAULT_URL_ATTRS = {
  a: ['href'],
  blockquote: ['cite'],
  img: ['src', 'srcset'],
  q: ['cite']
};

/** 协议白名单（相对 URL 无 scheme，始终放行到 URL 语法检查） */
export const DEFAULT_ALLOWED_PROTOCOLS = ['http:', 'https:', 'mailto:', 'tel:'];

/** data: 仅允许的图片 MIME（svg+xml 明确排除——SVG 可承载脚本） */
export const DEFAULT_ALLOWED_DATA_MIME = [
  'image/png', 'image/jpeg', 'image/gif', 'image/webp'
];

/**
 * DOM clobbering 敏感名 deny 列表（启发式，无法穷举，见 README 已知限制）。
 * 既拦截浏览器内置全局，也拦截常见业务配置对象名。
 */
export const DEFAULT_CLOBBER_DENY_IDS = [
  'a', 'abbr', 'address', 'applet', 'area', 'article', 'aside', 'audio',
  'b', 'base', 'bdi', 'bdo', 'blockquote', 'body', 'br', 'button',
  'canvas', 'caption', 'cite', 'code', 'col', 'colgroup', 'content',
  'data', 'datalist', 'dd', 'del', 'details', 'dfn', 'dialog', 'dir',
  'div', 'dl', 'dt',
  'element', 'embed',
  'fieldset', 'figcaption', 'figure', 'font', 'footer', 'form', 'frame', 'frameset',
  'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'head', 'header', 'hgroup', 'hr', 'html',
  'i', 'iframe', 'image', 'img', 'input', 'ins',
  'kbd',
  'label', 'legend', 'li', 'link',
  'main', 'map', 'mark', 'menu', 'meta', 'meter',
  'nav', 'nobr', 'noembed', 'noframes', 'noscript',
  'object', 'ol', 'optgroup', 'option', 'output',
  'p', 'param', 'picture', 'portal', 'pre', 'progress',
  'q',
  'rb', 'rp', 'rt', 'rtc', 'ruby',
  's', 'samp', 'script', 'search', 'section', 'select', 'slot', 'small',
  'source', 'span', 'strike', 'strong', 'style', 'sub', 'summary', 'sup',
  'table', 'tbody', 'td', 'template', 'textarea', 'tfoot', 'th', 'thead',
  'time', 'title', 'tr', 'track', 'tt', 'u', 'ul',
  'var', 'video',
  'xmp', 'x', 'y',
  // window/文档对象与常见业务名
  'window', 'document', 'location', 'navigator', 'history', 'screen',
  'top', 'parent', 'self', 'frames', 'global', 'globalthis',
  'sanitize', 'sanitizer', 'config', 'configuration', 'options', 'settings',
  'test', 'eval', 'parse', 'parser', 'escape', 'filter', 'policy', 'token',
  'auth', 'user', 'admin', 'api', 'app', 'store', 'state', 'data'
];

/** strict-css 预设：允许的 CSS 属性（声明式白名单，无 url/定位/脚本面） */
export const STRICT_CSS_ALLOWED_PROPERTIES = [
  'background-color', 'border', 'border-bottom', 'border-bottom-color',
  'border-bottom-style', 'border-bottom-width', 'border-collapse',
  'border-color', 'border-left', 'border-left-color', 'border-left-style',
  'border-left-width', 'border-right', 'border-right-color',
  'border-right-style', 'border-right-width', 'border-spacing',
  'border-style', 'border-top', 'border-top-color', 'border-top-style',
  'border-top-width', 'border-width',
  'caption-side', 'clear', 'color', 'direction',
  'empty-cells', 'font', 'font-family', 'font-size', 'font-style',
  'font-variant', 'font-weight', 'letter-spacing', 'line-height',
  'list-style', 'list-style-position', 'list-style-type',
  'opacity', 'orphans', 'outline', 'outline-color', 'outline-style',
  'outline-width', 'overflow', 'padding', 'padding-bottom', 'padding-left',
  'padding-right', 'padding-top', 'quotes', 'table-layout',
  'text-align', 'text-decoration', 'text-decoration-color',
  'text-decoration-line', 'text-decoration-style', 'text-indent',
  'text-transform', 'unicode-bidi', 'vertical-align', 'visibility',
  'white-space', 'widows', 'word-spacing', 'word-wrap'
];

/** strict-css 下即使属性合法也拒绝的危险值特征（小写匹配） */
export const CSS_FORBIDDEN_VALUE_PATTERNS = [
  'url(', 'expression(', '@import', 'javascript:', 'vbscript:',
  'data:', 'behavior:', '-moz-binding', 'attr('
];

/**
 * 严格默认配置。style 属性与 <style> 标签默认全部关闭
 * （此前被绕过的点，富文本需要排版时可在配置页切换 strictCss 预设）。
 */
export function createDefaultConfig() {
  return {
    schemaVersion: CONFIG_SCHEMA_VERSION,
    name: 'strict-default',
    tags: {
      allowed: [...DEFAULT_ALLOWED_TAGS],
      /** drop: 整个标签连同子树移除；unwrap（默认）: 仅去标签保留安全文本子节点 */
      dropWithContent: ['script', 'style', 'noscript', 'template', 'iframe',
        'object', 'embed', 'noembed', 'noframes', 'head', 'meta', 'link',
        'base', 'title', 'svg', 'math', 'plaintext', 'xmp']
    },
    attrs: {
      global: [...DEFAULT_GLOBAL_ATTRS],
      perTag: JSON.parse(JSON.stringify(DEFAULT_TAG_ATTRS)),
      /** name 属性全局丢弃（DOM clobbering 主入口） */
      dropNameAttr: true,
      /**
       * id 策略：默认 fail-closed（enabled=false → 所有 id 一律丢弃）。
       * 任何 id 都会进入 window 命名属性，是 DOM clobbering 的第二入口；
       * 业务确需锚点 id 时，在配置页显式开启并保留正则 + 敏感名 deny 双保险。
       */
      id: {
        enabled: false,
        pattern: '^[a-zA-Z][\\w-]{0,63}$',
        denyList: [...DEFAULT_CLOBBER_DENY_IDS]
      },
      /** 含 ASCII 控制字符的属性名/值整体拒绝 */
      rejectControlChars: true
    },
    url: {
      urlAttrs: JSON.parse(JSON.stringify(DEFAULT_URL_ATTRS)),
      allowedProtocols: [...DEFAULT_ALLOWED_PROTOCOLS],
      allowedDataMime: [...DEFAULT_ALLOWED_DATA_MIME],
      /** 允许相对 URL（无 scheme） */
      allowRelative: true,
      /** target=_blank 强制 rel=noopener */
      enforceNoopener: true
    },
    css: {
      /** style 属性默认关闭 */
      allowStyleAttr: false,
      /** <style> 标签默认关闭（标签本身也不在白名单） */
      allowStyleTag: false,
      strict: {
        allowedProperties: [...STRICT_CSS_ALLOWED_PROPERTIES],
        forbiddenValuePatterns: [...CSS_FORBIDDEN_VALUE_PATTERNS]
      }
    }
  };
}

/** strict-css 预设：在当前配置上开启 style 属性并套用严格 CSS 白名单（不动 <style> 标签） */
export function withStrictCss(config) {
  return {
    ...config,
    name: `${config.name}-strict-css`,
    css: {
      ...config.css,
      allowStyleAttr: true,
      allowStyleTag: false,
      strict: {
        allowedProperties: [...STRICT_CSS_ALLOWED_PROPERTIES],
        forbiddenValuePatterns: [...CSS_FORBIDDEN_VALUE_PATTERNS]
      }
    }
  };
}
