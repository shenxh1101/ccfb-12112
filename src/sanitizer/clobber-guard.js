/**
 * DOM clobbering 守卫（纯逻辑部分）。
 *
 * 两道闸：
 *  1. name 属性在 walker 中全局丢弃（clobbering 的主入口，含 window 命名属性与表单集合）；
 *  2. id 经正则白名单 + 敏感名 deny 列表收敛。
 * deny 列表是启发式的、无法穷举（见 README 已知限制），因此默认策略从严。
 */

import { hasControlChars } from './url-check.js';

/**
 * 校验 id 是否允许保留。
 * @returns {{ok:boolean, ruleId?:string, reason?:string}}
 */
export function checkId(value, idConfig) {
  // fail-closed：未显式启用 id 时，所有 id 一律拒绝
  if (!idConfig || idConfig.enabled !== true) {
    return { ok: false, ruleId: 'CLOBBER_ID_DISABLED', reason: 'id 默认关闭（fail-closed），任何 id 都会进入 window 命名属性，可用于 DOM clobbering' };
  }
  if (hasControlChars(value)) {
    return { ok: false, ruleId: 'CLOBBER_ID_CONTROL_CHAR', reason: 'id 含控制字符' };
  }
  let pattern;
  try {
    pattern = new RegExp(idConfig.pattern);
  } catch {
    return { ok: false, ruleId: 'CLOBBER_BAD_PATTERN', reason: 'id 白名单正则配置非法，fail-closed 拒绝' };
  }
  if (!pattern.test(value)) {
    return { ok: false, ruleId: 'CLOBBER_ID_PATTERN_DENY', reason: `id "${value}" 不符合白名单模式 ${idConfig.pattern}` };
  }
  if (idConfig.denyList && idConfig.denyList.includes(value.toLowerCase())) {
    return { ok: false, ruleId: 'CLOBBER_ID_DENY', reason: `id "${value}" 命中内置/业务敏感名 deny 列表，可用于 DOM clobbering` };
  }
  return { ok: true };
}
