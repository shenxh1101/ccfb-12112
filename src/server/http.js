/**
 * 零依赖静态文件服务 + REST API 的 HTTP 基础层。
 * 同时服务 Web 面板（src/web）与 harness 执行页（src/engine），
 * 解决 file:// 下 ES module 的 CORS 限制。
 */

import { createServer } from 'node:http';
import { readFile, stat } from 'node:fs/promises';
import { extname, join, normalize, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { dirname } from 'node:path';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = normalize(join(HERE, '../..'));

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.ico': 'image/x-icon'
};

/** 静态文件路由：/web/* → src/web，/engine/* → src/engine，/src/* → src */
function resolveStaticPath(urlPath) {
  const decoded = decodeURIComponent(urlPath.split('?')[0]);
  let rel;
  if (decoded === '/' || decoded === '') rel = '/src/web/index.html';
  else if (decoded.startsWith('/engine/')) rel = join('/src', decoded);   // /engine/x → /src/engine/x
  else if (decoded.startsWith('/sanitizer/')) rel = join('/src', decoded); // /sanitizer/x → /src/sanitizer/x
  else if (decoded.startsWith('/payloads/')) rel = join('/src', decoded);
  else if (decoded.startsWith('/src/')) rel = decoded;
  else if (decoded.startsWith('/web/')) rel = join('/src', decoded);      // /web/x → /src/web/x
  else return null;
  const abs = normalize(resolve(ROOT, '.' + rel));
  // 防目录穿越
  if (!abs.startsWith(ROOT)) return null;
  return abs;
}

export function createHttpServer({ apiHandler } = {}) {
  return createServer(async (req, res) => {
    try {
      if (req.url.startsWith('/api/')) {
        if (apiHandler) return apiHandler(req, res);
        res.writeHead(404).end(JSON.stringify({ error: 'no api handler' }));
        return;
      }
      const abs = resolveStaticPath(req.url);
      if (!abs) {
        res.writeHead(403).end('forbidden');
        return;
      }
      const info = await stat(abs).catch(() => null);
      if (!info || !info.isFile()) {
        res.writeHead(404).end('not found');
        return;
      }
      const data = await readFile(abs);
      res.writeHead(200, {
        'Content-Type': MIME[extname(abs)] || 'application/octet-stream',
        'Cache-Control': 'no-store'
      });
      res.end(data);
    } catch (e) {
      res.writeHead(500).end(JSON.stringify({ error: String(e) }));
    }
  });
}

/** 启动监听并返回实际端口（port=0 时系统分配） */
export function listen(server, port = 0, host = '127.0.0.1') {
  return new Promise((resolve) => {
    server.listen(port, host, () => resolve(server.address().port));
  });
}
