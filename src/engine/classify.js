/**
 * 把 harness 原始证据 + 网络事件 + 载荷期望，归类成最终扫描结论。
 * 状态：pass（挡住）/ bypass（脚本执行）/ clobbered / css-exfil / css-style-survive / error
 */
export function classifyResult(payload, raw, networkEvents) {
  if (raw?.error) {
    return base(payload, raw, 'error', `harness 执行异常: ${raw.error}`, []);
  }

  const canaryHost = payload.detect?.canary;
  const netHits = canaryHost
    ? networkEvents.filter(e => e.url.toLowerCase().includes(String(canaryHost).toLowerCase()))
    : networkEvents.filter(e => e.url.includes('.invalid'));

  const findings = [];

  // 1. 脚本真实执行（最强信号）
  if (raw?.executed && raw.events?.length) {
    findings.push(`检测到脚本执行事件: ${raw.events.map(e => `${e.kind}(${e.detail})`).join('; ')}`);
    return base(payload, raw, 'bypass', findings.join('；'), netHits);
  }

  // 2. CSS 外泄：期望 cssFetch 且抓到 .invalid canary 请求
  if (payload.expectation === 'cssFetch' && netHits.length > 0) {
    findings.push(`检测到 canary 外联请求: ${netHits.map(e => e.url).join(', ')}`);
    return base(payload, raw, 'css-exfil', findings.join('；'), netHits);
  }

  // 3. DOM clobbering：detect 表达式在子帧求值为 true
  if (payload.expectation === 'clobber' && raw?.clobbered === true) {
    findings.push(`clobber 判定表达式成立: ${payload.detect.expr}`);
    return base(payload, raw, 'clobbered', findings.join('；'), netHits);
  }

  // 4. 危险样式存活（视觉覆盖类）
  if (payload.expectation === 'cssStyle' && Array.isArray(raw?.styleApplied)) {
    const survived = raw.styleApplied.filter(c => c.actual && c.actual !== 'normal'
      && c.actual !== 'static' && c.actual !== 'auto');
    if (survived.length) {
      findings.push(`危险样式属性存活: ${survived.map(c => `${c.prop}=${c.actual}`).join(', ')}`);
      return base(payload, raw, 'css-style-survive', findings.join('；'), netHits);
    }
  }

  // 5. mXSS round-trip 变异
  if (raw?.roundTrip?.differs) {
    findings.push('净化输出经 fresh DOMParser 二次解析后结构发生变化（mXSS 变异面）');
    return base(payload, raw, 'bypass', findings.join('；'), netHits);
  }

  // 6. 期望 execute/clobber/cssFetch 但什么都没发生 → 成功挡住
  return base(payload, raw, 'pass', '未检测到脚本执行、clobber、外联或危险样式，载荷被挡住', netHits);
}

function base(payload, raw, status, conclusion, netHits) {
  return {
    payloadId: payload.id,
    category: payload.category,
    name: payload.name,
    status,
    conclusion,
    expectation: payload.expectation,
    sanitized: raw?.sanitized ?? null,
    trace: raw?.trace ?? [],
    stats: raw?.stats ?? null,
    roundTrip: raw?.roundTrip ?? null,
    evidence: {
      events: raw?.events ?? [],
      clobberDetail: raw?.clobberDetail ?? null,
      styleApplied: raw?.styleApplied ?? null,
      nodesSurvived: raw?.nodesSurvived ?? null,
      network: netHits.map(e => ({ url: e.url, method: e.method }))
    }
  };
}

/** 状态对应的展示元数据（结果页与 CLI 共用） */
export const STATUS_META = {
  'pass': { label: '已挡住', tone: 'ok' },
  'bypass': { label: '脚本执行（绕过）', tone: 'danger' },
  'clobbered': { label: 'DOM Clobbering 成立', tone: 'danger' },
  'css-exfil': { label: 'CSS 外联外泄', tone: 'danger' },
  'css-style-survive': { label: '危险样式存活', tone: 'warn' },
  'error': { label: '检测异常', tone: 'warn' }
};
