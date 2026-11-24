#!/usr/bin/env node
/**
 * CLI 扫描器（CI 门禁）：
 *   node bin/scan.mjs                         扫描全量载荷，默认严格配置
 *   node bin/scan.mjs --category protocol     只扫协议混淆类
 *   node bin/scan.mjs --config custom.json    使用自定义配置
 *   node bin/scan.mjs --json report.json      输出 JSON 报告
 * 默认配置下出现任何 bypass/clobber/css-exfil 即以非零码退出。
 */

import { readFile } from 'node:fs/promises';
import { createHttpServer, listen } from '../src/server/http.js';
import { ScanEngine } from '../src/engine/scan.js';
import { createDefaultConfig } from '../src/sanitizer/default-config.js';
import { migrateConfig } from '../src/server/store.js';
import { STATUS_META } from '../src/engine/classify.js';
import { CATEGORIES } from '../src/payloads/library.js';

function parseArgs(argv) {
  const args = { category: null, config: null, json: null, ids: null };
  for (let i = 2; i < argv.length; i++) {
    if (argv[i] === '--category') args.category = argv[++i];
    else if (argv[i] === '--config') args.config = argv[++i];
    else if (argv[i] === '--json') args.json = argv[++i];
    else if (argv[i] === '--ids') args.ids = argv[++i].split(',');
  }
  return args;
}

const args = parseArgs(process.argv);
let config = createDefaultConfig();
if (args.config) {
  config = migrateConfig(JSON.parse(await readFile(args.config, 'utf8')));
}

const server = createHttpServer();
const port = await listen(server, 0);
const engine = new ScanEngine({ baseUrl: `http://127.0.0.1:${port}` });

try {
  await engine.start();
  const report = await engine.scan({
    config,
    category: args.category,
    payloadIds: args.ids
  });

  if (args.json) {
    const { writeFile } = await import('node:fs/promises');
    await writeFile(args.json, JSON.stringify(report, null, 2));
  }

  // 控制台汇总
  console.log(`\n扫描配置: ${report.configName}  载荷数: ${report.total}`);
  for (const cat of CATEGORIES) {
    const rows = report.results.filter(r => r.category === cat.key);
    if (!rows.length) continue;
    console.log(`\n[${cat.name}]`);
    for (const r of rows) {
      const mark = r.status === 'pass' ? '✓' : '✗';
      console.log(`  ${mark} ${r.payloadId}  ${STATUS_META[r.status]?.label || r.status}  — ${r.name}`);
      if (r.status !== 'pass') console.log(`      ${r.conclusion}`);
    }
  }
  console.log('\n状态汇总:', JSON.stringify(report.byStatus));

  const failures = report.results.filter(r =>
    ['bypass', 'clobbered', 'css-exfil', 'css-style-survive'].includes(r.status));
  if (failures.length) {
    console.error(`\n✗ 安全门禁未通过：${failures.length} 条载荷未被挡住`);
    process.exitCode = 2;
  } else {
    console.log('\n✓ 全部攻击载荷已被默认配置挡住');
  }
} catch (e) {
  console.error('扫描失败:', e);
  process.exitCode = 1;
} finally {
  await engine.stop();
  server.close();
}
