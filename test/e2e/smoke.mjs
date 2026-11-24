/** 冒烟脚本：静态服务 → Chrome 启动 → harness 加载 → 单条载荷执行的完整链路 */
import { createHttpServer, listen } from '../../src/server/http.js';
import { ScanEngine } from '../../src/engine/scan.js';
import { createDefaultConfig } from '../../src/sanitizer/default-config.js';

const server = createHttpServer();
const port = await listen(server, 0);
const baseUrl = `http://127.0.0.1:${port}`;

const engine = new ScanEngine({ baseUrl });
try {
  await engine.start();
  console.log('[ok] Chrome + harness 就绪 @', baseUrl);
  const report = await engine.scan({
    config: createDefaultConfig(),
    payloadIds: ['classic-01', 'classic-02', 'clobber-01', 'css-02']
  });
  for (const r of report.results) {
    console.log(`${r.payloadId} [${r.status}] ${r.name} -> ${r.conclusion}`);
    console.log(`   sanitized: ${r.sanitized}`);
  }
  console.log('\n汇总:', JSON.stringify(report.byStatus));
} catch (e) {
  console.error('[fail]', e);
  process.exitCode = 1;
} finally {
  await engine.stop();
  server.close();
}
