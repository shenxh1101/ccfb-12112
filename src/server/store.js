/**
 * 文件存储层：当前生效配置、配置快照、扫描历史。
 * 数据落 data/ 目录（已在 .gitignore）。零依赖，JSON 读写。
 */

import { readFile, writeFile, mkdir, readdir, rm } from 'node:fs/promises';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createDefaultConfig, CONFIG_SCHEMA_VERSION } from '../sanitizer/default-config.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const DATA_DIR = join(HERE, '..', '..', 'data');
const CONFIG_PATH = join(DATA_DIR, 'config.json');
const SCANS_DIR = join(DATA_DIR, 'scans');

async function ensureDirs() {
  await mkdir(SCANS_DIR, { recursive: true });
}

/** 读取生效配置；不存在则写入并返回严格默认配置 */
export async function loadConfig() {
  await ensureDirs();
  try {
    const raw = await readFile(CONFIG_PATH, 'utf8');
    const parsed = JSON.parse(raw);
    return migrateConfig(parsed);
  } catch {
    const def = createDefaultConfig();
    await saveConfig(def);
    return def;
  }
}

export async function saveConfig(config) {
  await ensureDirs();
  const validated = migrateConfig(config);
  await writeFile(CONFIG_PATH, JSON.stringify(validated, null, 2), 'utf8');
  return validated;
}

export async function resetConfig() {
  const def = createDefaultConfig();
  await saveConfig(def);
  return def;
}

/** 配置 schema 版本校验与迁移（当前仅 v1，预留迁移钩子） */
export function migrateConfig(config) {
  if (!config || typeof config !== 'object') {
    throw new Error('配置必须是 JSON 对象');
  }
  if (config.schemaVersion && config.schemaVersion > CONFIG_SCHEMA_VERSION) {
    throw new Error(`配置 schemaVersion=${config.schemaVersion} 高于当前支持的 ${CONFIG_SCHEMA_VERSION}，请升级工具`);
  }
  // 结构完整性兜底：缺关键段时 fail-closed，回退默认
  for (const section of ['tags', 'attrs', 'url', 'css']) {
    if (!config[section] || typeof config[section] !== 'object') {
      throw new Error(`配置缺少必需段: ${section}`);
    }
  }
  return { ...config, schemaVersion: config.schemaVersion || CONFIG_SCHEMA_VERSION };
}

/** 导出：返回可分享的 JSON 文本 */
export async function exportConfig() {
  const cfg = await loadConfig();
  return JSON.stringify({ exportedAt: new Date().toISOString(), tool: 'xss-sanitizer-range', config: cfg }, null, 2);
}

/** 导入：校验后覆盖生效配置 */
export async function importConfig(jsonText) {
  let parsed;
  try {
    parsed = JSON.parse(jsonText);
  } catch (e) {
    throw new Error(`导入失败：不是合法 JSON（${e.message}）`);
  }
  const config = parsed.config || parsed; // 兼容裸配置与导出包裹两种形态
  return saveConfig(config);
}

export async function saveScan(report) {
  await ensureDirs();
  const path = join(SCANS_DIR, `${report.id}.json`);
  await writeFile(path, JSON.stringify(report, null, 2), 'utf8');
  return path;
}

export async function listScans() {
  await ensureDirs();
  const files = (await readdir(SCANS_DIR)).filter(f => f.endsWith('.json')).sort().reverse();
  return files.map(f => f.replace(/\.json$/, ''));
}

export async function loadScan(id) {
  const safe = id.replace(/[^a-zA-Z0-9_-]/g, '');
  return JSON.parse(await readFile(join(SCANS_DIR, `${safe}.json`), 'utf8'));
}

export async function clearScans() {
  await ensureDirs();
  for (const f of await readdir(SCANS_DIR)) {
    await rm(join(SCANS_DIR, f), { force: true });
  }
}
