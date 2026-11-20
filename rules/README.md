# Semgrep 规则集说明

## sql-injection.yaml

面向 Python / Java 的 SQL 注入（CWE-89）规则，仅覆盖**字面量拼接/插值后直接执行**这一模式，属于高置信、低噪声子集。

| 规则 ID | 语言 | 命中模式 | 严重度 |
| --- | --- | --- | --- |
| `python-sqli-fstring-execute` | Python | `cur.execute(f"...")` | ERROR |
| `python-sqli-concat-execute` | Python | `execute("..." + x)` / `"..." % x` / `"...".format(x)` | ERROR |
| `java-sqli-statement-concat` | Java | `st.executeQuery("..." + x)`、`executeUpdate`、`execute` | ERROR |
| `java-sqli-string-format` | Java | `st.executeQuery(String.format(...))` | ERROR |

校验与运行：

```bash
semgrep --validate --config rules/sql-injection.yaml
semgrep --config rules/sql-injection.yaml samples/ --json
```

当前样本期望命中 6 条（见根目录 README 的对应表）。

## 已知缺口

- **变量间接传递**：`sql = "...".format(x)` 之后再 `cur.execute(sql)`，单条 pattern 无法追踪，需要 `mode: taint`（v0.2）
- **动态 SQL 框架**：MyBatis `${}`、SQLAlchemy `text()`、JPA 原生查询
- **数字型参数**：`int()` 转换后的拼接通常不可注入，需在判定层结合类型证据处理，避免跟随规则误报

## 编写约定

- 必须带 `metadata.cwe`、`metadata.confidence`
- `message` 用中文一句话说明风险 + 一句修复建议
- 新规则必须附样本并更新 README 对应表
