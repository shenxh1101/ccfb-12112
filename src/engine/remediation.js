/**
 * 修复建议引擎：根据扫描中绕过的证据 + trace ruleId，生成可一键应用的配置补丁。
 * 纯函数，输入扫描结果与当前配置，输出建议列表；应用动作由 store/server 执行。
 */

/**
 * 为单条绕过结果生成修复建议。
 * @returns {Array<{id, title, reason, ruleIds, patch:(config)=>config}>}
 */
export function buildRemediations(scanResult, config) {
  const advice = [];
  const seen = new Set();

  const push = (item) => {
    if (seen.has(item.id)) return;
    seen.add(item.id);
    advice.push(item);
  };

  for (const r of scanResult.results) {
    if (r.status === 'pass' || r.status === 'error') continue;
    const traceRules = new Set(r.trace.map(t => t.ruleId));

    // 1. 外内容命名空间（SVG/Math）相关绕过
    if (r.category === 'mxss' || traceRules.has('TAG_FOREIGN_DROP') === false && /svg|math/i.test(r.sanitized || '')) {
      if (config.tags.allowed.includes('svg') || config.tags.allowed.includes('math')) {
        push({
          id: 'remove-foreign-tags',
          title: '从标签白名单移除 svg / math（外内容命名空间）',
          reason: 'SVG/MathML 外内容解析规则与 HTML 不同，历史绕过高发；mXSS 载荷依赖命名空间切换。',
          ruleIds: ['TAG_FOREIGN_DROP'],
          patch: (cfg) => ({
            ...cfg,
            tags: {
              ...cfg.tags,
              allowed: cfg.tags.allowed.filter(t => t !== 'svg' && t !== 'math'),
              dropWithContent: unique([...cfg.tags.dropWithContent, 'svg', 'math'])
            }
          })
        });
      }
    }

    // 2. style 属性/标签相关
    if (r.status === 'css-exfil' || r.status === 'css-style-survive' ||
        r.sanitized?.includes('style=') || r.category === 'css') {
      if (config.css.allowStyleAttr) {
        push({
          id: 'disable-style-attr',
          title: '关闭 style 属性（回到默认禁用）',
          reason: 'CSS url()/@import/属性选择器可外泄数据，position 可做视觉覆盖；style 是此前的绕过点。',
          ruleIds: ['ATTR_DROP_STYLE', 'CSS_ATTR_DROP_ALL', 'CSS_VALUE_DENY'],
          patch: (cfg) => ({ ...cfg, css: { ...cfg.css, allowStyleAttr: false } })
        });
      }
      if (config.css.allowStyleTag) {
        push({
          id: 'disable-style-tag',
          title: '关闭 <style> 标签',
          reason: '<style> 内 @import/@font-face/属性选择器是数据外泄通道，默认配置不开启。',
          ruleIds: ['TAG_DROP', 'CSS_AT_RULE_DENY'],
          patch: (cfg) => ({
            ...cfg,
            css: { ...cfg.css, allowStyleTag: false },
            tags: {
              ...cfg.tags,
              dropWithContent: unique([...cfg.tags.dropWithContent, 'style'])
            }
          })
        });
      }
    }

    // 3. 危险协议
    if (r.evidence.network?.length || traceRules.has('URL_SCHEME_DENY') === false &&
        /javascript:|vbscript:|data:text\/html|data:image\/svg/i.test(r.sanitized || '')) {
      push({
          id: 'tighten-protocols',
          title: '收敛 URL 协议白名单并禁用危险 data: MIME',
          reason: 'javascript:/vbscript: 可执行脚本，data:text/html 与 data:image/svg+xml 可承载活动内容。',
          ruleIds: ['URL_SCHEME_DENY', 'URL_DATA_MIME_DENY', 'URL_CONTROL_CHAR'],
          patch: (cfg) => ({
            ...cfg,
            url: {
              ...cfg.url,
              allowedProtocols: ['http:', 'https:', 'mailto:', 'tel:'],
              allowedDataMime: ['image/png', 'image/jpeg', 'image/gif', 'image/webp']
            }
          })
        });
    }

    // 4. DOM clobbering
    if (r.status === 'clobbered') {
      if (!cfg_dropName(config)) {
        push({
          id: 'drop-name-attr',
          title: '全局丢弃 name 属性',
          reason: 'name 是 window 命名属性与表单集合 clobbering 的主入口。',
          ruleIds: ['ATTR_DROP_NAME'],
          patch: (cfg) => ({ ...cfg, attrs: { ...cfg.attrs, dropNameAttr: true } })
        });
      }
      push({
        id: 'tighten-id-policy',
        title: '收紧 id 策略（正则白名单 + 敏感名 deny）',
        reason: 'id 同样进入 window 命名属性，需要模式校验与敏感名拒绝双保险。',
        ruleIds: ['CLOBBER_ID_DENY', 'CLOBBER_ID_PATTERN_DENY'],
        patch: (cfg) => ({
          ...cfg,
          attrs: {
            ...cfg.attrs,
            id: { enabled: true, pattern: '^[a-zA-Z][\\w-]{0,63}$', denyList: cfg.attrs.id?.denyList || [] }
          }
        })
      });
    }

    // 5. 事件属性 / 标签白名单兜底
    if (r.status === 'bypass' && /onerror|onload|on\w+=/i.test(r.sanitized || '')) {
      push({
        id: 'deny-event-attrs',
        title: '确保所有 on* 事件属性被拒',
        reason: '事件处理属性是最直接的脚本执行入口，必须无差别拒绝。',
        ruleIds: ['ATTR_DROP_EVENT'],
        patch: (cfg) => cfg // 默认配置已拒绝，这里作为显式确认项
      });
    }
  }

  return advice;
}

function cfg_dropName(config) {
  return config.attrs?.dropNameAttr === true;
}

function unique(arr) {
  return [...new Set(arr)];
}

/** 应用一条建议，返回新配置（不可变更新） */
export function applyPatch(config, adviceItem) {
  return structuredClone(adviceItem.patch(structuredClone(config)));
}
