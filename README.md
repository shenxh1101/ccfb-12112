# XSS 靶场 + 自研白名单 HTML 净化器

富文本编辑器净化模块上线前的本地 XSS 审计工具。零第三方依赖（仅 Node 内置模块），
扫描时把净化后的 HTML 真实挂进无头 Chrome 的 sandbox iframe 中**执行**，
而不是做字符串匹配。默认严格配置下，内置 51 条攻击载荷全部被挡住。

## 能力一览

- **自研白名单净化器**：标签 / 属性 / 协议 / CSS 全部可配置，默认配置从严；
- **四类专项载荷库 + 基线回归**：mXSS、DOM clobbering、CSS 注入、协议混淆，共 51 条可复现用例；
- **真实执行检测**：无头 Chrome + CDP，sandbox iframe 内挂加载净化结果，
  捕获脚本执行、DOM clobber、CSS 外联外泄、危险样式存活，并做 fresh 解析 round-trip；
- **决策可追溯**：每个放行/拒绝动作都带稳定 `ruleId` 与原因，扫描结果可看到「哪条规则放的行」；
- **修复闭环**：按绕过根因聚合配置补丁建议，一键应用后自动重新扫描并对比；
- **老接口兼容**：`sanitize(html)` 签名不变；
- **配置导入导出**：带 schema 版本的 JSON，团队可共享。

## 快速开始

```bash
npm start            # 启动面板，默认 http://127.0.0.1:8127 （PORT 可改）
npm run scan         # CLI 全量扫描，默认严格配置，有绕过则非零退出（CI 门禁）
npm test             # 纯逻辑单测（node:test，无需浏览器）
npm run test:e2e     # 端到端：拉起无头 Chrome 跑全量载荷 + 检测能力回归
```

环境要求：Node ≥ 20（开发于 v22）、本机装有 Google Chrome / Chromium，
或通过 `CHROME_PATH` 环境变量指定可执行文件。

## 四个页面

| 页面 | 能做什么 |
| --- | --- |
| 载荷库 | 按分类浏览 51 条载荷的原始向量、原理、参考链接与检测方式，勾选后单条试跑 |
| 净化器配置 | 分级编辑标签/属性/协议/CSS，原始 JSON 直接改，导入导出、恢复默认、切换 strict-css |
| 扫描结果 | 每条载荷状态、净化输出、外联/执行/clobber 证据、完整 ruleId 决策 trace |
| 修复建议 | 按根因聚合的配置补丁，一键应用并自动重扫，前后结果对比 |

## 架构

```
src/
├── sanitizer/          净化器（浏览器与 Node 同构 ESM）
│   ├── default-config  严格默认配置 + strict-css 预设
│   ├── parser          DOMParser(text/html) 封装（不手写 tokenizer）
│   ├── walker          白名单树遍历 + ruleId 决策 trace
│   ├── serializer      自研显式序列化器（不依赖 innerHTML 直出）
│   ├── url-check       协议白名单 / 控制字符 / srcset 逐条校验
│   ├── css-guard       可选 strict-css 声明式白名单
│   ├── clobber-guard   name 全局丢弃 + id fail-closed
│   └── legacy          window.sanitize(html) 老接口兼容层
├── payloads/           五类结构化载荷
├── engine/
│   ├── chrome          零依赖 CDP 客户端 + 无头 Chrome 进程管理
│   ├── harness(.html)  沙箱 iframe 执行、内联 hook、证据收集
│   ├── scan            扫描编排 + .invalid canary 网络监控
│   ├── classify        证据 → pass/bypass/clobbered/css-exfil 判定
│   └── remediation     绕过证据 → 配置补丁
├── server/             node:http 静态服务 + REST API + JSON 存储
└── web/                原生 ESM 单页四 tab（无构建步骤）
```

### 为什么这样设计

- **解析交给浏览器 DOMParser，序列化自己写**：手写 HTML tokenizer 本身就是 mXSS 高发点；
  平台解析器对实体、SVG/Math 外内容、foster parenting 的处理与最终渲染一致。
  序列化统一转义、显式输出，规避 `innerHTML` 在外内容命名空间下的实体变异。
- **外内容命名空间无差别拒绝**：SVG/MathML 是历史绕过高发区（本项目此前的绕过点就在 svg/style），
  默认标签白名单不含 svg/math，walker 对非 HTML 命名空间整树拒绝。
- **style 默认全关**：CSS `url()/@import/@font-face/属性选择器` 可外泄数据，`position` 可视觉覆盖。
  需要排版时可在配置页开启 strict-css 预设（属性白名单 + 危险值特征拦截）。
- **name 全局丢弃、id 默认 fail-closed**：DOM clobbering 同时依赖 name 与 id 进入 window 命名属性，
  双管齐下才能保证库内 clobber 用例全灭。
- **含控制字符的属性名/值整体拒绝**：不做「先剥字符再判断」，避免 `java\tscript:` 类剥字符换义绕过。
- **canary 用 `.invalid` 保留域名**：RFC 2606/6761 保证不可解析、不外发真实流量，
  DNS 失败本身即外泄证据。

## 检测通道

每条载荷在独立 sandbox iframe（`allow-scripts allow-same-origin`，srcdoc 继承受控父源）中执行：

1. 文档 preamble 内联 hook `alert/confirm/prompt/print/error`，命中即 postMessage 上报，
   并给 `window.__canary` 赋本次载荷 id；CDP 层另有一层 `addScriptToEvaluateOnNewDocument` 兜底；
2. CDP Network 监听 `*.invalid` 请求，覆盖 CSS 外泄；
3. 载荷自带 detect 表达式在子帧真实 window 上求值，判定 DOM clobbering；
4. 渲染后程序化点击所有 `a[href]`，覆盖 `javascript:` 导航类；
5. computed-style 检查危险样式存活；
6. fresh DOMParser 二次解析 + 同一序列化器 round-trip，捕获 mXSS 变异面；
7. 异步等待窗口 850ms，覆盖定时器 / 动画类延迟触发。

## 默认配置下的验收结论

`npm run test:e2e` 与 `npm run scan` 均确认：**51 条载荷全部 pass，0 绕过、0 检测异常**。
同时用一份故意放宽（开启 `javascript:` 协议）的配置回归，确认检测器能稳定报出 5 条绕过，
证明净化器与检测器没有同时失灵。

## 已知限制（显式声明）

1. **id deny 列表是启发式的**：无法穷举所有可能被业务代码裸引用的全局名。默认 fail-closed
   （拒绝一切 id）规避该问题；若业务开启 id，根治仍需避免全局名裸引用。
2. **净化器只保证输出 HTML 在标准浏览器 HTML 上下文下安全**：若业务把净化结果拼进
   JS 字符串、URL、`document.write` 或非常规上下文，不在保证范围，需在对应上下文另行编码。
3. **strict-css 预设收窄但不消除 CSS 攻击面**：新 CSS 属性/特性持续出现，默认关闭 style 即规避；
   开启后应跟随本项目更新白名单。
4. **检测基于当前版本 Chrome 的解析/执行语义**：其他引擎或老旧内嵌 webview（如 IE 系 expression/vbscript）
   行为可能不同；这类向量在净化器侧已默认拒绝，但执行检测不会在现代 Chrome 复现其成功执行。
5. **sandbox iframe 用了 allow-same-origin**：因为父 harness 需要读 contentDocument 做 clobber/样式检查。
   父页面是本地受控页面、无业务数据；脚本执行由 preamble hook 与 CDP 网络监控双重捕获。

## CLI

```bash
node bin/scan.mjs [--category mxss|clobbering|css|protocol|classic]
                  [--config custom.json] [--ids id1,id2] [--json report.json]
```

退出码：`0` 全部挡住；`2` 存在绕过；`1` 扫描本身出错。
