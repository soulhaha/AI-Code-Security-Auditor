#!/usr/bin/env bash
# 本地回归：校验规则 → 扫描样本 → 生成上下文，全部通过才返回 0。
set -euo pipefail
cd "$(dirname "$0")/.."

semgrep --validate --config rules/sql-injection.yaml
semgrep --config rules/sql-injection.yaml samples/ --json --output semgrep.json
python3 core/context_extractor.py --semgrep-json semgrep.json --format json > contexts.json

python3 - <<'PY'
import json

findings = json.load(open("semgrep.json", encoding="utf-8"))["results"]
contexts = json.load(open("contexts.json", encoding="utf-8"))
assert len(findings) == 6, f"expected 6 findings, got {len(findings)}"
assert len(contexts) == 6, f"expected 6 contexts, got {len(contexts)}"
assert all(c["function"] for c in contexts), "context without enclosing function"
for c in contexts:
    print(f'{c["file"]}:{c["line"]} -> {c["function"]["name"]} / {c["sink"]}')
print("OK: 6 findings, 6 contexts")
PY
