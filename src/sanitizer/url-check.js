/**
 * URL / 协议白名单校验（纯逻辑，Node 与浏览器同构，无 DOM 依赖）。
 *
 * 重点防协议混淆：
 *  - 原始值含 ASCII 控制字符（含 NUL/tab/换行）直接拒绝，不做"先剥离再判断"，
 *    避免 jav\ta\tscript: 这类剥字符后换义的绕过；
 *  - HTML 实体在 DOMParser 阶段已解码，这里看到的就是解码后的真实值；
 *  - scheme 以第一个冒号定位，冒号前出现 / ? # 则视为相对路径；
 *  - data: 仅 img 上的图片 MIME 可用，svg+xml 明确拒绝（SVG 可承载脚本）。
 */

const CONTROL_CHAR_RE = /[\u0000-\u001f\u007f]/;
const BOM_AND_WS = /^[﻿\s]+|[\s]+$/g;

export function hasControlChars(value) {
  return typeof value === 'string' && CONTROL_CHAR_RE.test(value);
}

/** 去掉首尾空白与 BOM；不动字符串内部字符 */
export function trimOuter(value) {
  return String(value).replace(BOM_AND_WS, '');
}

/** 提取 scheme（小写、不含冒号）；无 scheme 返回 null */
export function extractScheme(value) {
  const colon = value.indexOf(':');
  if (colon === -1) return null;
  const head = value.slice(0, colon);
  // 冒号前出现路径/查询/片段分隔符 → 这是相对 URL，不是 scheme
  if (/[\/?#]/.test(head)) return null;
  return head.toLowerCase();
}

/**
 * 校验单个 URL 值。
 * @param {string} raw 属性原始值（DOMParser 已解码实体）
 * @param {{tag:string, attr:string}} ctx 标签/属性上下文
 * @param {object} urlConfig config.url
 * @returns {{ok:boolean, ruleId?:string, detail?:string, normalized:string}}
 */
export function checkUrl(raw, ctx, urlConfig) {
  const normalized = trimOuter(raw);
  if (normalized === '') {
    return { ok: false, ruleId: 'URL_EMPTY', normalized };
  }
  if (hasControlChars(raw)) {
    return { ok: false, ruleId: 'URL_CONTROL_CHAR', detail: 'URL 含 ASCII 控制字符/NUL，疑似协议混淆', normalized };
  }

  const scheme = extractScheme(normalized);

  if (scheme === null) {
    // 相对 URL（/path、path、//host 等）
    if (!urlConfig.allowRelative) {
      return { ok: false, ruleId: 'URL_RELATIVE_DENIED', normalized };
    }
    return { ok: true, normalized };
  }

  if (urlConfig.allowedProtocols.includes(`${scheme}:`)) {
    return { ok: true, normalized };
  }

  if (scheme === 'data') {
    // 仅 img[src] 允许 data:，且 MIME 受限
    if (ctx.tag !== 'img' || ctx.attr !== 'src') {
      return { ok: false, ruleId: 'URL_SCHEME_DENY', detail: 'data: 仅允许出现在 img[src]', normalized };
    }
    const mime = parseDataMime(normalized);
    if (mime && urlConfig.allowedDataMime.includes(mime.toLowerCase())) {
      return { ok: true, normalized };
    }
    return { ok: false, ruleId: 'URL_DATA_MIME_DENY', detail: `data: MIME 不被允许: ${mime || 'unknown'}（svg+xml 可承载脚本，明确拒绝）`, normalized };
  }

  return {
    ok: false,
    ruleId: 'URL_SCHEME_DENY',
    detail: `协议 "${scheme}:" 不在白名单 ${urlConfig.allowedProtocols.join(', ')}`,
    normalized
  };
}

/** 解析 data:<mime>;base64,... 的 MIME 部分 */
export function parseDataMime(value) {
  const m = /^data:([^,;]*)/i.exec(value);
  if (!m) return null;
  return m[1].trim().toLowerCase() || 'text/plain';
}

/**
 * 解析 srcset（逗号分隔候选，描述符与 URL 间以空白分隔）。
 * data URI 内部的逗号不做切分：data: 候选直接吃到下一个 " , " 边界。
 * @returns {Array<{url:string, descriptor:string}>}
 */
export function parseSrcset(raw) {
  const candidates = [];
  let i = 0;
  const n = raw.length;
  while (i < n) {
    while (i < n && /\s/.test(raw[i])) i++;
    if (i >= n) break;
    let start = i;
    if (raw.slice(i, i + 5).toLowerCase() === 'data:') {
      // data URI：base64 段内部可能含逗号。吃到"逗号之后出现空白"（描述符起点或候选分隔）为止
      let seenComma = false;
      while (i < n) {
        const ch = raw[i];
        if (ch === ',') seenComma = true;
        if (seenComma && /\s/.test(ch)) break;
        i++;
      }
    } else {
      while (i < n && !/[\s,]/.test(raw[i])) i++;
    }
    const url = raw.slice(start, i);
    while (i < n && /\s/.test(raw[i])) i++;
    start = i;
    while (i < n && raw[i] !== ',') i++;
    const descriptor = raw.slice(start, i).trim();
    if (url) candidates.push({ url, descriptor });
    if (raw[i] === ',') i++;
  }
  return candidates;
}

/**
 * 校验整个 srcset：每个候选 URL 都必须通过协议校验。
 * @returns {{ok:boolean, ruleId?:string, detail?:string, badUrl?:string}}
 */
export function checkSrcset(raw, ctx, urlConfig) {
  if (hasControlChars(raw)) {
    return { ok: false, ruleId: 'URL_CONTROL_CHAR', detail: 'srcset 含 ASCII 控制字符' };
  }
  const candidates = parseSrcset(raw);
  if (candidates.length === 0) {
    return { ok: false, ruleId: 'SRCSET_EMPTY' };
  }
  for (const c of candidates) {
    const r = checkUrl(c.url, ctx, urlConfig);
    if (!r.ok) return { ...r, badUrl: c.url };
  }
  return { ok: true };
}
