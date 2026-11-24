/** 载荷库聚合入口：所有类别 + 检索辅助 */
import mxss from './categories/mxss.js';
import clobbering from './categories/clobbering.js';
import css from './categories/css.js';
import protocol from './categories/protocol.js';
import classic from './categories/classic.js';
import { CATEGORIES } from './schema.js';

export const PAYLOADS = [
  ...mxss,
  ...clobbering,
  ...css,
  ...protocol,
  ...classic
];

export { CATEGORIES };

export function getPayloadById(id) {
  return PAYLOADS.find(p => p.id === id) || null;
}

export function payloadsByCategory(category) {
  return category ? PAYLOADS.filter(p => p.category === category) : PAYLOADS;
}

export function categorySummary() {
  return CATEGORIES.map(c => ({
    ...c,
    count: PAYLOADS.filter(p => p.category === c.key).length
  }));
}
