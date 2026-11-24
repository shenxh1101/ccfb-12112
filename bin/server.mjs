#!/usr/bin/env node
import { createApp } from '../src/server/server.js';

const port = Number(process.env.PORT) || 8127;
const app = await createApp({ port });
console.log('');
console.log('  XSS 靶场 + 白名单净化器 已启动');
console.log(`  面板地址:  ${app.url}`);
console.log('  按 Ctrl+C 退出');
console.log('');

const shutdown = async () => {
  await app.close();
  process.exit(0);
};
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
