/**
 * 浏览器端 harness：运行在无头 Chrome 的普通页面里。
 * 职责：调用净化器 → 把结果挂进 sandbox iframe（opaque origin）真实执行 →
 * 收集 canary 执行事件 / clobber 判定 / 样式检查 → 再做一次 fresh 解析 round-trip。
 *
 * 跨 frame 的脚本钩子由 Node 侧通过 CDP addScriptToEvaluateOnNewDocument 注入
 * （见 scan.js），本文件只负责 frame 生命周期与结果汇总。
 */

import { sanitize } from '../sanitizer/index.js';
import { serializeRoot } from '../sanitizer/serializer.js';

const EXEC_WAIT_MS = 850;

/** 注入到每个 frame（含嵌套 srcdoc）世界的钩子源码；命中即写 top.__canaryEvents */
export const FRAME_HOOK_SOURCE = `
(function () {
  if (window.__canaryHooked) return;
  window.__canaryHooked = true;
  var topRef = (function () { try { return top; } catch (e) { return null; } })();
  function report(kind, detail) {
    try {
      (topRef || window).__canaryEvents = (topRef || window).__canaryEvents || [];
      (topRef || window).__canaryEvents.push({
        kind: kind, detail: String(detail), href: location.href, ts: Date.now()
      });
    } catch (e) { /* 跨 origin 时静默，CDP 侧仍有 console 兜底 */ }
  }
  var canary = function (v) { report('alert', v); };
  try { window.alert = canary; } catch (e) {}
  try { window.confirm = function (v) { report('confirm', v); return false; }; } catch (e) {}
  try { window.prompt = function (v) { report('prompt', v); return null; }; } catch (e) {}
  try { window.print = function () { report('print', 'print'); }; } catch (e) {}
  // Error 构造捕获（部分载荷用 throw/错误处理侧信道）
  window.addEventListener('error', function (e) {
    report('error', (e.message || '') + ' @ ' + (e.filename || ''));
  });
})();
`;

/**
 * 生成每个 sandbox frame 文档最前面的 preamble。
 * 直接内联 hook（不依赖 CDP addScriptToEvaluateOnNewDocument 对子帧的注入时序）：
 *  - 给 window.__canary 赋本次载荷 id；
 *  - 劫持 alert/confirm/prompt/print，命中即 postMessage 给父 harness；
 *  - 捕获全局 error 事件。
 * frame 与父同源（allow-same-origin），postMessage 必然可达。
 */
function framePreamble(payloadId) {
  return `<script>
  (function () {
    window.__canary = ${JSON.stringify(payloadId)};
    function send(kind, detail) {
      parent.postMessage({ __canary: true, kind: kind, detail: String(detail),
        payloadId: ${JSON.stringify(payloadId)}, href: location.href }, '*');
    }
    window.alert = function (v) { send('alert', v); };
    window.confirm = function (v) { send('confirm', v); return false; };
    window.prompt = function (v) { send('prompt', v); return null; };
    window.print = function () { send('print', 'print'); };
    window.addEventListener('error', function (e) {
      send('error', (e.message || '') + ' @ ' + (e.filename || ''));
    });
  })();
<\/script>`;
}

/**
 * 执行单个作业。
 * @param {object} job { payload, config, roundTrip }
 * @returns {object} 净化输出、执行事件、clobber 结果、样式结果
 */
export async function runJob(job) {
  const { payload, config, roundTrip = false } = job;
  const result = sanitize(payload.vector, { config, trace: true });
  let html = result.html;

  // mXSS round-trip：用 fresh DOMParser 再解析一次净化输出并重新序列化，
  // 比较两次"序列化后的 HTML"是否一致。必须用同一个序列化器，
  // 不能拿 outerHTML/文本节点拼接，否则格式差异会被误判成结构变异。
  let roundTripHtml = null;
  let roundTripDiffers = false;
  if (roundTrip) {
    const reparsed = new DOMParser().parseFromString(html, 'text/html');
    const frag = reparsed.createDocumentFragment();
    while (reparsed.body.firstChild) frag.appendChild(reparsed.body.firstChild);
    roundTripHtml = serializeRoot(frag);
    roundTripDiffers = normalize(html) !== normalize(roundTripHtml);
  }

  const eventsBefore = window.__canaryEvents ? window.__canaryEvents.length : 0;
  const frame = await mountSandboxFrame(html, payload.id);
  await wait(EXEC_WAIT_MS);

  // 主动交互：点击 frame 内所有链接，触发 javascript: 导航类载荷
  await clickAllLinks(frame);
  await wait(200);

  const evidence = collectEvidence(frame, payload, eventsBefore);
  if (frame.parentNode) document.body.removeChild(frame);

  return {
    payloadId: payload.id,
    sanitized: html,
    trace: result.trace,
    stats: result.stats,
    roundTrip: roundTrip ? { html: roundTripHtml, differs: roundTripDiffers } : null,
    ...evidence
  };
}

/** 全局接收子帧 postMessage 的 canary 事件 */
if (typeof globalThis !== 'undefined' && globalThis.addEventListener) {
  globalThis.addEventListener('message', (ev) => {
    if (ev.data && ev.data.__canary) {
      globalThis.__canaryEvents = globalThis.__canaryEvents || [];
      globalThis.__canaryEvents.push({
        kind: ev.data.kind,
        detail: ev.data.detail,
        payloadId: ev.data.payloadId,
        href: ev.data.href,
        ts: Date.now()
      });
    }
  });
}

function mountSandboxFrame(html, id) {
  return new Promise((resolve, reject) => {
    const frame = document.createElement('iframe');
    // allow-scripts + allow-same-origin：srcdoc 继承父源，父 harness 才能读取
    // contentDocument/contentWindow 做 clobber 表达式与样式检查。
    // 父页面本身是本地受控 harness（无业务数据），同源不引入额外风险；
    // 脚本执行由 preamble 内联 hook + Node 侧 CDP 网络监控兜底。
    frame.setAttribute('sandbox', 'allow-scripts allow-same-origin');
    frame.dataset.payloadId = id;
    frame.style.width = '1px';
    frame.style.height = '1px';
    frame.onload = () => resolve(frame);
    frame.onerror = reject;
    // preamble 在文档最前面执行，先于载荷内任何脚本，设置 canary 并 hook
    frame.srcdoc = framePreamble(id) + html;
    document.body.appendChild(frame);
  });
}

async function clickAllLinks(frame) {
  try {
    const doc = frame.contentDocument;
    if (!doc) return;
    for (const a of doc.querySelectorAll('a[href]')) {
      try { a.click(); } catch { /* sandbox 导航被拦也记录不到执行，视为安全 */ }
      await wait(10);
    }
  } catch {
    // opaque origin 下 contentDocument 可能抛 SecurityError——预期行为
  }
}

function collectEvidence(frame, payload, eventsBefore) {
  const allEvents = window.__canaryEvents || [];
  const events = allEvents.slice(eventsBefore).map(e => ({ ...e }));

  const evidence = {
    executed: events.length > 0,
    events,
    clobbered: false,
    clobberDetail: null,
    styleApplied: null,
    nodesSurvived: null
  };

  // clobber 判定表达式在子帧 window 上求值（用子帧自己的 Function，保证全局名解析在子帧）
  if (payload.detect?.expr) {
    try {
      const win = frame.contentWindow;
      const value = win.eval(`(${payload.detect.expr})`);
      evidence.clobbered = value === true;
      evidence.clobberDetail = { expr: payload.detect.expr, value };
    } catch (e) {
      evidence.clobberDetail = { expr: payload.detect.expr, error: String(e) };
    }
  }

  // 样式存活检查（视觉覆盖类）
  if (payload.detect?.style && frame.contentDocument) {
    try {
      const el = frame.contentDocument.querySelector('*[style]');
      if (el) {
        const cs = frame.contentWindow.getComputedStyle(el);
        const checks = Object.entries(payload.detect.style).map(([k, v]) => ({
          prop: k, expected: v, actual: cs.getPropertyValue(k)
        }));
        evidence.styleApplied = checks;
      }
    } catch (e) {
      evidence.styleApplied = { error: String(e) };
    }
  }

  // 存活节点概览（结果页展示净化后还剩什么）
  try {
    evidence.nodesSurvived = [...frame.contentDocument.body.querySelectorAll('*')]
      .map(n => n.tagName.toLowerCase())
      .slice(0, 20);
  } catch { /* ignore */ }

  return evidence;
}

function normalize(s) {
  return String(s).replace(/\s+/g, ' ').trim();
}

function wait(ms) {
  return new Promise(r => setTimeout(r, ms));
}
