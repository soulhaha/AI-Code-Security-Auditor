# AI-Code-Security-Auditor

轻量级 AI 辅助代码安全审计原型：**Semgrep 静态规则 → 代码上下文抽取 → LLM 误报过滤**。

静态扫描器召回高但误报多；本项目的目标不是替代 Scanner，而是给它加一层"会看上下文"的判定器：把告警还原成函数级上下文，再交给 LLM 判断是否真的可利用，并给出理由与修复建议。

## 特性

- **CodeContextExtractor**：零第三方依赖（Python 3.9+），从 `文件 + 行号` 或 `semgrep --json` 抽取结构化上下文：所属函数/类、导入、参数与 source 线索、sink 调用、窗口源码
- **Semgrep 规则集**：SQL 注入（CWE-89）4 条规则，覆盖 f-string、`%`/`str.format`/`+` 拼接、Java `Statement` 拼接与 `String.format`
- **可复现样本**：Python / Java 各含漏洞样本与安全正例，用于规则回归
- **设计文档**：AI 误报过滤 Agent 的判定契约、Prompt、评估与降级策略
- **路线图**：从原型到 v1.0 的分版本计划与验收标准

## 目录结构

```
.
├── core/
│   └── context_extractor.py     # CodeContextExtractor 核心实现
├── rules/
│   ├── sql-injection.yaml       # Semgrep SQL 注入规则
│   └── README.md                # 规则说明与期望命中
├── samples/
│   ├── python/vuln_sqli.py      # Python 漏洞样本
│   └── java/VulnSqli.java       # Java 漏洞样本
├── docs/
│   ├── ai-fp-filter-agent.md    # AI 误报过滤 Agent 设计文档
│   └── roadmap.md               # 路线图与开发计划
├── .github/workflows/ci.yml     # 规则校验 + 样本回归
└── CHANGELOG.md
```

## 快速开始

```bash
# 1) 安装 Semgrep（仅扫描需要，上下文抽取器本身零依赖）
pip install semgrep

# 2) 校验规则并扫描样本
semgrep --validate --config rules/sql-injection.yaml
semgrep --config rules/sql-injection.yaml samples/ --json --output semgrep.json

# 3) 单个告警点抽取上下文
python3 core/context_extractor.py samples/python/vuln_sqli.py 18 --radius 8

# 4) 批量：把 Semgrep 结果整体转成上下文
python3 core/context_extractor.py --semgrep-json semgrep.json --format markdown
```

输出示例（节选）：

```json
{
  "file": "samples/python/vuln_sqli.py",
  "language": "python",
  "line": 18,
  "sink": "cur.execute",
  "function": {"name": "find_user_fstring", "start_line": 16, "signature": "def find_user_fstring(name: str):"},
  "imports": ["import sqlite3", "import sys"],
  "sources": [{"line": 16, "kind": "parameter", "code": "name"}],
  "window": [10, 26],
  "code": "16 | def find_user_fstring(name: str):\n17 |     cur = connect().cursor()\n18 |     cur.execute(f\"...\")"
}
```

## 样本与规则对应

| 文件 | 行 | 规则 | 说明 |
| --- | --- | --- | --- |
| samples/python/vuln_sqli.py | 18 | `python-sqli-fstring-execute` | f-string 插值 |
| samples/python/vuln_sqli.py | 25 | `python-sqli-concat-execute` | `%` 格式化 |
| samples/python/vuln_sqli.py | 40 | `python-sqli-concat-execute` | 字符串拼接 |
| samples/java/VulnSqli.java | 21 | `java-sqli-statement-concat` | Statement 拼接 |
| samples/java/VulnSqli.java | 27 | `java-sqli-string-format` | `String.format` |
| samples/java/VulnSqli.java | 33 | `java-sqli-statement-concat` | `executeUpdate` 拼接 |

已知缺口：`samples/python/vuln_sqli.py:33`（先拼 SQL 赋值再执行）需要污点规则，当前版本未覆盖，见 [roadmap v0.2](./docs/roadmap.md)。

## 文档

- [AI 误报过滤 Agent 设计文档](./docs/ai-fp-filter-agent.md)：架构、输入输出契约、Prompt、评估指标、成本控制、隐私与限制
- [路线图与开发计划](./docs/roadmap.md)：v0.1 → v1.0 里程碑、任务拆分、风险与版本节奏
- [规则说明](./rules/README.md)

## 路线图摘要

| 版本 | 主题 | 状态 |
| --- | --- | --- |
| v0.1 | 原型可跑通（抽取器 + 规则 + 样本 + 设计稿） | ✅ |
| v0.2 | 污点规则、跨文件 source、pytest、SARIF | 🚧 |
| v0.3 | LLM Judge 接入、缓存、评估集与指标 | 📋 |
| v0.4 | JavaScript/Go、规则包拆分 | 📋 |
| v1.0 | CLI 一体化、Docker、文档站 | 📋 |

## 使用边界

本项目用于**自有代码或已授权目标**的安全审计与规则研究；`samples/` 中的代码为**故意引入漏洞的教学样本**，请勿复制到生产项目。

## License

[MIT](./LICENSE)
