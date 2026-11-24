/**
 * REST API + 静态服务入口。
 * 路由：
 *   GET  /api/payloads            载荷库（含分类汇总）
 *   GET  /api/config              当前配置
 *   PUT  /api/config              保存配置
 *   POST /api/config/reset        恢复默认
 *   GET  /api/config/export       导出 JSON
 *   POST /api/config/import       导入 JSON
 *   POST /api/scan                启动扫描 {category?, payloadIds?}
 *   GET  /api/scans               扫描历史列表
 *   GET  /api/scans/:id           单次扫描详情
 *   GET  /api/remediation/:scanId 修复建议
 *   POST /api/remediation/apply   应用建议 {scanId, adviceId, rescan}
 */

import { createHttpServer, listen } from './http.js';
import {
  loadConfig, saveConfig, resetConfig, exportConfig, importConfig,
  saveScan, listScans, loadScan
} from './store.js';
import { PAYLOADS, CATEGORIES, categorySummary, getPayloadById } from '../payloads/library.js';
import { ScanEngine } from '../engine/scan.js';
import { buildRemediations, applyPatch } from '../engine/remediation.js';
import { STATUS_META } from '../engine/classify.js';

export async function createApp({ port = 0 } = {}) {
  // 复用单个 Chrome 实例；首次扫描时惰性启动
  let engine = null;
  const getEngine = async (baseUrl) => {
    if (!engine) engine = new ScanEngine({ baseUrl });
    if (!engine.page) await engine.start();
    return engine;
  };

  const apiHandler = async (req, res) => {
    const json = (code, body) => {
      res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8' });
      res.end(JSON.stringify(body));
    };
    const readBody = () => new Promise((resolve, reject) => {
      let data = '';
      req.on('data', c => { data += c; if (data.length > 5e6) reject(new Error('body too large')); });
      req.on('end', () => resolve(data));
      req.on('error', reject);
    });
    const path = req.url.split('?')[0];

    try {
      // ---- 载荷库 ----
      if (path === '/api/payloads' && req.method === 'GET') {
        return json(200, { categories: categorySummary(), payloads: PAYLOADS, statusMeta: STATUS_META });
      }

      // ---- 配置 ----
      if (path === '/api/config' && req.method === 'GET') {
        return json(200, await loadConfig());
      }
      if (path === '/api/config' && req.method === 'PUT') {
        const body = JSON.parse(await readBody());
        return json(200, await saveConfig(body));
      }
      if (path === '/api/config/reset' && req.method === 'POST') {
        return json(200, await resetConfig());
      }
      if (path === '/api/config/export' && req.method === 'GET') {
        res.writeHead(200, {
          'Content-Type': 'application/json; charset=utf-8',
          'Content-Disposition': 'attachment; filename="sanitizer-config.json"'
        });
        return res.end(await exportConfig());
      }
      if (path === '/api/config/import' && req.method === 'POST') {
        const text = await readBody();
        return json(200, await importConfig(text));
      }

      // ---- 扫描 ----
      if (path === '/api/scan' && req.method === 'POST') {
        const body = JSON.parse((await readBody()) || '{}');
        const config = await loadConfig();
        const baseUrl = `http://127.0.0.1:${actualPort}`;
        const scanEngine = await getEngine(baseUrl);
        const report = await scanEngine.scan({
          config,
          category: body.category || null,
          payloadIds: body.payloadIds || null
        });
        await saveScan(report);
        return json(200, report);
      }
      if (path === '/api/scans' && req.method === 'GET') {
        return json(200, { scans: await listScans() });
      }
      const scanMatch = path.match(/^\/api\/scans\/([\w-]+)$/);
      if (scanMatch && req.method === 'GET') {
        try {
          return json(200, await loadScan(scanMatch[1]));
        } catch {
          return json(404, { error: '扫描记录不存在' });
        }
      }

      // ---- 修复建议 ----
      const remMatch = path.match(/^\/api\/remediation\/([\w-]+)$/);
      if (remMatch && req.method === 'GET') {
        const scan = await loadScan(remMatch[1]);
        const config = await loadConfig();
        return json(200, { advice: buildRemediations(scan, config) });
      }
      if (path === '/api/remediation/apply' && req.method === 'POST') {
        const { scanId, adviceId, rescan = true } = JSON.parse(await readBody());
        const scan = await loadScan(scanId);
        const config = await loadConfig();
        const advice = buildRemediations(scan, config).find(a => a.id === adviceId);
        if (!advice) return json(404, { error: '修复建议不存在或已不适用' });
        const nextConfig = await saveConfig(applyPatch(config, advice));
        let newScan = null;
        if (rescan) {
          const baseUrl = `http://127.0.0.1:${actualPort}`;
          const scanEngine = await getEngine(baseUrl);
          newScan = await scanEngine.scan({ config: nextConfig, category: scan.category });
          await saveScan(newScan);
        }
        return json(200, { config: nextConfig, advice, rescan: newScan });
      }

      return json(404, { error: `未知路由 ${req.method} ${path}` });
    } catch (e) {
      return json(400, { error: String(e.message || e) });
    }
  };

  const server = createHttpServer({ apiHandler });
  const actualPort = await listen(server, port);

  return {
    port: actualPort,
    url: `http://127.0.0.1:${actualPort}`,
    async close() {
      if (engine) await engine.stop();
      server.close();
    }
  };
}
