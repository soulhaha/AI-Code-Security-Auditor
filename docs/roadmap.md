# 项目路线图与开发计划

> 当前：**v0.1 原型** · 更新于 2026-11

## 1. 里程碑总览

| 版本 | 主题 | 关键交付物 | 状态 |
| --- | --- | --- | --- |
| v0.1 | 原型可跑通 | CodeContextExtractor、SQLi 规则集、Python/Java 样本、AI 过滤设计稿 | ✅ 已完成 |
| v0.2 | 上下文增强 | Python/Java 污点规则、跨语句传播、SARIF 输出、单测 | 🚧 进行中 |
| v0.3 | Agent 落地 | LLM Judge 接入、判定缓存、评估集与指标看板 | 📋 计划中 |
| v0.4 | 多语言扩展 | JavaScript/Go 支持、规则包拆分、上下文裁剪策略 | 📋 计划中 |
| v1.0 | 可用版本 | CLI 一体化（scan → context → judge → report）、Docker 镜像、文档站 | 📋 计划中 |

## 2. v0.1（已完成）

- [x] `core/context_extractor.py`：零依赖上下文抽取，支持单点与 `semgrep --json` 批量输入，输出 JSON/Markdown
- [x] `rules/sql-injection.yaml`：4 条 SQL 注入规则（f-string、拼接/格式化、Statement 拼接、String.format）
- [x] `samples/`：Python 4 处漏洞 + 1 处正例；Java 3 处漏洞 + 1 处正例
- [x] `docs/ai-fp-filter-agent.md`：判定契约、Prompt、评估与降级策略
- [x] 规则校验与样本回归可复现（见 README 快速开始）

## 3. v0.2 详细计划（2–3 周）

| 任务 | 说明 | 产出 | 优先级 |
| --- | --- | --- | --- |
| 污点规则 | 用 Semgrep `mode: taint` 覆盖"先拼 SQL 再执行"（样本第 33 行当前漏报） | `rules/sql-injection-taint.yaml` | P0 |
| 跨文件 source | Flask/Django/Spring 入口参数识别，补齐 source 定义 | 规则 + 样本 | P0 |
| 单元测试 | 抽取器与规则期望命中数的 pytest 用例 | `tests/` | P0 |
| SARIF 输出 | `--format sarif`，接入 GitHub Code Scanning | `core/report.py` | P1 |
| 上下文裁剪 | 长函数按"签名 + sink ±20 行 + source 行"压缩 | 抽取器增强 | P1 |
| 规则元数据 | 统一 `confidence`、`likelihood`、`impact`，供阈值聚合 | 规则规范 | P2 |

验收：样本集漏报从 1 条降到 0；`pytest` 全绿；CI 产出 SARIF 工件。

## 4. v0.3 详细计划（3–4 周）

- LLM Judge：OpenAI 兼容接口，JSON schema 强校验，支持本地模型（Ollama/vLLM）
- 判定缓存：内容哈希 + prompt 版本，命中率目标 ≥ 60%
- 评估集：300 条人工标注（Python/Java 各半），脚本输出 P/R/F1 与成本报告
- 报告：Markdown 汇总 + 按规则/文件聚合的误报过滤率
- 提示词注入防护：注释中的指令一律忽略，输出不执行任何代码建议

验收：FPR 相对 Semgrep 基线下降 ≥ 50%，recall ≥ 90%，单条成本 ≤ 3k tokens。

## 5. v0.4+ 与长期方向

- 语言扩展：JavaScript/TypeScript、Go、PHP（各自 sink 表 + 规则包）
- 规则生态：按 CWE 组织规则包，支持社区贡献与版本化
- 上下文图：函数调用图 + 数据流图，支持跨文件判定
- 自动修复建议：diff 级 patch（人工确认后应用），不作为默认行为
- 集成：GitHub App / GitLab CI / IDE 插件（VS Code 诊断）

## 6. 待办池（Backlog）

| 事项 | 备注 |
| --- | --- |
| MyBatis `${}` / SQLAlchemy `text()` 专项规则 | 动态 SQL 框架，误报与漏报都集中在这里 |
| Java 反序列化、命令注入规则包 | 与 SQLi 共用上下文抽取与判定流程 |
| 多告警聚类 | 同函数同根因合并，降低复核成本 |
| 数据集版本化 | 标注集与 prompt 版本绑定，支持回放 |
| 性能优化 | 大仓库增量扫描、上下文缓存落盘 |

## 7. 风险与应对

| 风险 | 影响 | 应对 |
| --- | --- | --- |
| LLM 判定不稳定 | 结论不可复现 | 温度 0 + 固定 prompt 版本 + 缓存 |
| `needs_review` 占比过高 | 人工成本降不下来 | 按规则聚类定向优化，补 few-shot |
| 跨文件污点缺失 | 漏报 | v0.2 taint 规则 + 调用图补全 |
| 代码外发合规 | 无法落地企业环境 | 私有化模型 / 脱敏 / 离线模式 |
| 规则与框架演进 | 规则腐化 | CI 回归 + 样本随版本更新 |

## 8. 版本节奏

- 双周迭代，每个版本一个可演示的端到端产线
- 每版本更新 `CHANGELOG.md` 与评估报告
- 评估指标下降 > 3% 阻断合入
