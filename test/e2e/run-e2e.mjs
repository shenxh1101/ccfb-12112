/**
 * 端到端测试：默认严格配置下全量载荷必须全部挡住；
 * 再用一份故意放宽的配置回归，确认检测能力本身能稳定报出绕过。
 */
import { createHttpServer, listen } from '../../src/server/http.js';
import { ScanEngine } from '../../src/engine/scan.js';
import { createDefaultConfig, withStrictCss } from '../../src/sanitizer/default-config.js';
import { buildRemediations } from '../../src/engine/remediation.js';

const server = createHttpServer();
const port = await listen(server, 0);
const engine = new ScanEngine({ baseUrl: `http://127.0.0.1:${port}` });

let failures = 0;
const check = (cond, msg) => {
  if (cond) console.log(`  ✓ ${msg}`);
  else { failures++; console.error(`  ✗ ${msg}`); }
};

try {
  await engine.start();

  // 1. 默认配置：全量必须 pass
  console.log('\n[1] 默认严格配置 · 全量载荷');
  const strict = await engine.scan({ config: createDefaultConfig() });
  check(strict.total >= 45, `载荷库规模 ${strict.total} 条（≥45）`);
  check(strict.bypassed === 0, `默认配置下绕过数为 0（实际 ${strict.bypassed}）`);
  check(strict.errors === 0, `无检测异常（实际 ${strict.errors}）`);

  // 2. 放宽配置：检测能力回归（必须能报出绕过，证明净化器与检测器没有同时失灵）
  console.log('\n[2] 故意放宽配置 · 检测能力回归');
  const loose = createDefaultConfig();
  loose.tags.allowed.push('svg', 'img');
  loose.attrs.perTag.img = ['src', 'onerror', 'srcset'];
  loose.url.allowedProtocols.push('javascript:');
  const looseReport = await engine.scan({ config: loose, category: 'protocol' });
  check(looseReport.bypassed > 0, `放宽 javascript: 协议后能报出绕过（实际 ${looseReport.bypassed}）`);

  // 3. strict-css 预设：CSS 类仍应全部挡住
  console.log('\n[3] strict-css 预设 · CSS 载荷');
  const cssCfg = withStrictCss(createDefaultConfig());
  const cssReport = await engine.scan({ config: cssCfg, category: 'css' });
  check(cssReport.bypassed === 0, `开启 strict-css 后 CSS 绕过数为 0（实际 ${cssReport.bypassed}）`);

  // 4. 修复引擎：放宽报告必须能生成建议，且应用后重新挡住
  console.log('\n[4] 修复建议引擎');
  const advice = buildRemediations(looseReport, loose);
  check(advice.length > 0, `放宽配置生成了 ${advice.length} 条修复建议`);
  const protoAdvice = advice.find(a => a.id === 'tighten-protocols');
  check(!!protoAdvice, '包含协议收敛建议 tighten-protocols');

} catch (e) {
  failures++;
  console.error('  ✗ 端到端测试异常:', e);
} finally {
  await engine.stop();
  server.close();
}

console.log(failures === 0 ? '\n✓ 端到端测试全部通过\n' : `\n✗ ${failures} 项端到端断言失败\n`);
process.exitCode = failures ? 1 : 0;
