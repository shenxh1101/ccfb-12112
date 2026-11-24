/**
 * 扫描编排：拉起 Chrome → 打开 harness 页 → 逐载荷执行 → 汇总判定。
 * 网络侧通过 CDP Network 域监听 *.invalid canary 请求（CSS 外泄证据）。
 */

import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { launchChrome, CdpConnection, createPage, evalInPage } from './chrome.js';
import { PAYLOADS, payloadsByCategory } from '../payloads/library.js';
import { FRAME_HOOK_SOURCE } from './harness.js';
import { classifyResult } from './classify.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const HARNESS_HTML = join(HERE, 'harness.html');

export class ScanEngine {
  /**
   * @param {object} [opts]
   * @param {string} [opts.baseUrl] HTTP 基址（由 server 提供静态服务）；
   *   提供时 harness 走 http://，否则退回 file://（module 会被 CORS 拦截，仅调试用）
   */
  constructor({ baseUrl = null } = {}) {
    this.baseUrl = baseUrl;
    this.chrome = null;
    this.cdp = null;
    this.page = null;
    this.networkEvents = [];
  }

  async start() {
    this.chrome = await launchChrome();
    this.cdp = new CdpConnection(this.chrome.wsUrl);
    await this.cdp.ready;

    // 自动附加到所有 frame（含 srcdoc 子帧），在文档世界创建前注入钩子
    await this.cdp.send('Target.setAutoAttach', {
      autoAttach: true,
      waitForDebuggerOnStart: true,
      flatten: true
    });
    this.cdp.on('Target.attachedToTarget', (params) => {
      // 同步连续下发：CDP 保证同一 session 上命令按发送顺序执行，
      // 先注入文档前脚本再放行 debugger 等待
      this.cdp.send('Page.addScriptToEvaluateOnNewDocument', {
        source: FRAME_HOOK_SOURCE
      }, params.sessionId).catch(() => {});
      this.cdp.send('Runtime.runIfWaitingForDebugger', {}, params.sessionId).catch(() => {});
    });

    this.page = await createPage(this.cdp, { url: 'about:blank' });

    // 网络监控：记录所有请求，scan 时按 canary 主机过滤
    this.cdp.on('Network.requestWillBeSent', (params, sessionId) => {
      this.networkEvents.push({
        url: params.request.url,
        method: params.request.method,
        sessionId,
        ts: params.timestamp
      });
    });

    // 打开 harness 页：优先 HTTP（ES module 需要 http(s) 源），退回 file://
    const harnessUrl = this.baseUrl
      ? `${this.baseUrl}/engine/harness.html`
      : `file://${HARNESS_HTML}`;
    await this.page.send('Page.navigate', { url: harnessUrl });
    await this.waitForHarnessReady();
  }

  async waitForHarnessReady() {
    const deadline = Date.now() + 10000;
    while (Date.now() < deadline) {
      try {
        const ready = await evalInPage(this.page, 'window.__harnessReady === true');
        if (ready) return;
      } catch { /* 页面还在加载 */ }
      await new Promise(r => setTimeout(r, 100));
    }
    throw new Error('harness 页面初始化超时');
  }

  /**
   * 运行扫描。
   * @param {object} opts { config, category, payloadIds }
   */
  async scan(opts = {}) {
    if (!this.page) await this.start();
    const { config, category = null, payloadIds = null } = opts;
    let targets = payloadIds
      ? PAYLOADS.filter(p => payloadIds.includes(p.id))
      : payloadsByCategory(category);

    const startedAt = new Date().toISOString();
    const results = [];
    for (const payload of targets) {
      const netBefore = this.networkEvents.length;
      const job = { payload, config, roundTrip: true };
      let raw;
      try {
        raw = await evalInPage(this.page,
          `window.__harness.runJob(${JSON.stringify(job).replace(/<\/script>/g, '<\\/script>')})`,
          { awaitPromise: true });
      } catch (e) {
        raw = { payloadId: payload.id, error: String(e) };
      }
      const netAfter = this.networkEvents.slice(netBefore)
        .filter(e => e.url.includes('.invalid'));
      results.push(classifyResult(payload, raw, netAfter));
    }

    const summary = summarize(results);
    return {
      id: `scan-${Date.now()}`,
      startedAt,
      finishedAt: new Date().toISOString(),
      configName: config?.name || 'ad-hoc',
      category,
      total: results.length,
      ...summary,
      results
    };
  }

  async stop() {
    try { await this.cdp?.close(); } catch { /* ignore */ }
    await this.chrome?.close();
    this.chrome = null;
    this.cdp = null;
    this.page = null;
  }
}

function summarize(results) {
  const byStatus = {};
  for (const r of results) byStatus[r.status] = (byStatus[r.status] || 0) + 1;
  return {
    byStatus,
    blocked: results.filter(r => r.status === 'pass').length,
    bypassed: results.filter(r => r.status !== 'pass' && r.status !== 'error').length,
    errors: results.filter(r => r.status === 'error').length
  };
}
