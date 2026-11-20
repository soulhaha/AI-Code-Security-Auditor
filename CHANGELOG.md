# Changelog

## v0.1.0 — 2026-11

首个原型版本。

- 新增 `core/context_extractor.py`：`CodeContextExtractor`，支持单点与 `semgrep --json` 批量上下文抽取，输出 JSON / Markdown
- 新增 `rules/sql-injection.yaml`：4 条 SQL 注入规则（Python f-string、拼接/格式化、Java Statement 拼接、String.format）
- 新增样本：`samples/python/vuln_sqli.py`（4 处漏洞 + 1 处正例）、`samples/java/VulnSqli.java`（3 处漏洞 + 1 处正例）
- 新增 `docs/ai-fp-filter-agent.md`：误报过滤 Agent 设计文档（契约、Prompt、评估、成本、隐私）
- 新增 `docs/roadmap.md`：v0.1 → v1.0 路线图
- 新增 CI：规则校验 + 样本回归 + 上下文生成

已知缺口：变量间接传递的注入（先赋值再执行）未覆盖，将在 v0.2 用 taint 规则补齐。
