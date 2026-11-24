/**
 * 零依赖 CDP（Chrome DevTools Protocol）客户端与无头 Chrome 进程管理。
 * 仅使用 Node 内置 child_process / fs / http / WebSocket（Node 22 全局）。
 */

import { spawn } from 'node:child_process';
import { mkdtemp, rm, readFile } from 'node:fs/promises';
import { accessSync, constants } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createServer } from 'node:net';
import { setTimeout as delay } from 'node:timers/promises';

const CHROME_CANDIDATES = [
  '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
  '/Applications/Chromium.app/Contents/MacOS/Chromium',
  '/usr/bin/google-chrome',
  '/usr/bin/chromium',
  '/usr/bin/chromium-browser'
];

export function findChrome() {
  for (const p of CHROME_CANDIDATES) {
    try {
      accessSync(p, constants.X);
      return p;
    } catch { /* try next */ }
  }
  return process.env.CHROME_PATH || null;
}

/** 让操作系统分配一个空闲 TCP 端口并立即释放，交给 Chrome 绑定 */
function getFreePort() {
  return new Promise((resolve, reject) => {
    const srv = createServer();
    srv.unref();
    srv.on('error', reject);
    srv.listen(0, '127.0.0.1', () => {
      const { port } = srv.address();
      srv.close(() => resolve(port));
    });
  });
}

/**
 * 启动无头 Chrome 并返回进程与 CDP 基础信息。
 * 调用方负责在结束时调用 chrome.close()。
 */
export async function launchChrome() {
  const binary = findChrome();
  if (!binary) {
    throw new Error('未找到 Chrome/Chromium，可设置环境变量 CHROME_PATH 指定可执行文件路径');
  }
  const port = await getFreePort();
  const userDataDir = await mkdtemp(join(tmpdir(), 'xss-range-chrome-'));
  const args = [
    '--headless=new',
    '--disable-gpu',
    '--no-first-run',
    '--no-default-browser-check',
    '--disable-extensions',
    '--disable-popup-blocking',
    `--remote-debugging-port=${port}`,
    `--user-data-dir=${userDataDir}`,
    'about:blank'
  ];
  const proc = spawn(binary, args, { stdio: ['ignore', 'pipe', 'pipe'] });
  let stderr = '';
  proc.stderr.on('data', d => { stderr += d.toString(); });

  // 父进程（CLI/测试）异常退出时确保 Chrome 不孤儿；
  // 长驻 server 走自己的 SIGINT/SIGTERM close() 流程
  const orphanGuard = () => {
    if (!proc.killed) proc.kill('SIGKILL');
  };
  process.once('exit', orphanGuard);
  proc.once('exit', () => process.removeListener('exit', orphanGuard));

  const wsUrl = await waitForDevTools(proc, port, () => stderr);
  return {
    process: proc,
    wsUrl,
    port,
    userDataDir,
    async close() {
      proc.kill('SIGTERM');
      await delay(300);
      if (!proc.killed) proc.kill('SIGKILL');
      await rm(userDataDir, { recursive: true, force: true });
    }
  };
}

async function waitForDevTools(proc, port, getStderr) {
  const deadline = Date.now() + 15000;
  let lastErr;
  while (Date.now() < deadline) {
    if (proc.exitCode !== null) {
      throw new Error(`Chrome 启动即退出: ${getStderr().slice(-500)}`);
    }
    try {
      const res = await fetch(`http://127.0.0.1:${port}/json/version`);
      if (res.ok) {
        const info = await res.json();
        if (info.webSocketDebuggerUrl) return info.webSocketDebuggerUrl;
      }
    } catch (e) { lastErr = e; }
    await delay(120);
  }
  throw new Error(`等待 Chrome DevTools 超时 (port ${port}): ${lastErr?.message || 'unknown'}`);
}

/** 极简 CDP 连接：支持命令/响应与事件，自动管理 message id */
export class CdpConnection {
  constructor(wsUrl) {
    this.ws = new WebSocket(wsUrl);
    this.nextId = 1;
    this.pending = new Map();
    this.eventHandlers = new Map();
    this.sessions = new Map(); // sessionId -> 自身副本
    this.ready = new Promise((resolve, reject) => {
      this.ws.addEventListener('open', () => resolve());
      this.ws.addEventListener('error', e => reject(new Error(`CDP WebSocket 错误: ${e.message || 'unknown'}`)));
    });
    this.ws.addEventListener('message', ev => this.onMessage(JSON.parse(ev.data)));
    this.close = this.close.bind(this);
  }

  onMessage(msg) {
    if (msg.id && this.pending.has(msg.id)) {
      const { resolve, reject } = this.pending.get(msg.id);
      this.pending.delete(msg.id);
      if (msg.error) reject(new Error(`${msg.error.message} (code ${msg.error.code})`));
      else resolve(msg.result);
      return;
    }
    if (msg.method) {
      const handlers = this.eventHandlers.get(msg.method);
      if (handlers) for (const h of handlers) h(msg.params, msg.sessionId);
    }
  }

  on(method, handler) {
    if (!this.eventHandlers.has(method)) this.eventHandlers.set(method, new Set());
    this.eventHandlers.get(method).add(handler);
  }

  async send(method, params = {}, sessionId) {
    await this.ready;
    const id = this.nextId++;
    const payload = { id, method, params };
    if (sessionId) payload.sessionId = sessionId;
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      this.ws.send(JSON.stringify(payload));
    });
  }

  async close() {
    try { this.ws.close(); } catch { /* already closed */ }
  }
}

/** 连接浏览器级 CDP，并创建一个新页面 target，返回带 session 的页面对象 */
export async function createPage(cdp, { url = 'about:blank' } = {}) {
  const { targetId } = await cdp.send('Target.createTarget', { url });
  const { sessionId } = await cdp.send('Target.attachToTarget', {
    targetId,
    flatten: true
  });
  const page = {
    targetId,
    sessionId,
    send(method, params) { return cdp.send(method, params, sessionId); }
  };
  await page.send('Page.enable');
  await page.send('Runtime.enable');
  await page.send('Network.enable');
  return page;
}

/** 在页面上下文求值，默认把返回值 JSON 化，抛错时带异常文本 */
export async function evalInPage(page, expression, { awaitPromise = true, returnByValue = true } = {}) {
  const result = await page.send('Runtime.evaluate', {
    expression,
    awaitPromise,
    returnByValue,
    userGesture: true
  });
  if (result.exceptionDetails) {
    const exc = result.exceptionDetails.exception?.description || result.exceptionDetails.text;
    const err = new Error(`页面执行异常: ${exc}`);
    err.cdpException = result.exceptionDetails;
    throw err;
  }
  return result.result?.value;
}

/** 读取一个本地文件为 UTF-8 字符串（供注入 harness 脚本） */
export async function readLocalFile(path) {
  return readFile(path, 'utf8');
}
