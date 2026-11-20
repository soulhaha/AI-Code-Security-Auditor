#!/usr/bin/env python3
"""CodeContextExtractor — 从静态扫描告警抽取结构化代码上下文。

输入：文件 + 行号（或 semgrep --json 输出）
输出：JSON / Markdown，包含所属函数、类、导入、告警行、源码窗口、source 线索

设计目标：零第三方依赖、可离线运行、输出稳定，可直接喂给 LLM 做误报过滤。
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path

LANG_BY_SUFFIX = {".py": "python", ".java": "java"}

FUNC_PATTERN = {
    "python": re.compile(r"^(?P<indent>\s*)(?:async\s+)?def\s+(?P<name>[A-Za-z_]\w*)\s*\("),
    "java": re.compile(
        r"^\s*(?:(?:public|private|protected|static|final|synchronized|abstract)\s+)+"
        r"[\w<>\[\],.?\s]+?\s+(?P<name>[A-Za-z_]\w*)\s*\([^;]*\)\s*"
        r"(?:throws\s+[\w,.\s]+)?\{"
    ),
}

CLASS_PATTERN = {
    "python": re.compile(r"^(?P<indent>\s*)class\s+(?P<name>[A-Za-z_]\w*)"),
    "java": re.compile(
        r"^\s*(?:public|private|protected)?\s*(?:final\s+|abstract\s+)?class\s+(?P<name>[A-Za-z_]\w*)"
    ),
}

SOURCE_HINT = re.compile(
    r"(request\.(?:args|form|values|json|GET|POST)|input\(|sys\.argv|os\.environ|"
    r"getParameter|@RequestParam|getHeader|getCookies|HttpServletRequest|Scanner\()"
)

KNOWN_SINKS = {
    "execute", "executemany", "executeQuery", "executeUpdate", "raw", "text",
    "queryForObject", "queryForList", "query", "update",
}

SINK_CALL = re.compile(r"\b([A-Za-z_][\w.]*)\s*\(")


@dataclass
class FunctionInfo:
    name: str
    start_line: int
    signature: str
    class_name: str | None = None


@dataclass
class CodeContext:
    file: str
    language: str
    line: int
    rule_id: str = ""
    severity: str = ""
    message: str = ""
    sink: str | None = None
    function: FunctionInfo | None = None
    imports: list[str] = field(default_factory=list)
    sources: list[dict] = field(default_factory=list)
    window: list[int] = field(default_factory=list)
    code: str = ""


def detect_language(path: Path) -> str:
    return LANG_BY_SUFFIX.get(path.suffix.lower(), "other")


def read_lines(path: Path) -> list[str]:
    return path.read_text(encoding="utf-8", errors="replace").splitlines()


def _signature(line: str) -> str:
    return line.strip()[:200]


def find_enclosing_function(lines: list[str], line_no: int, language: str) -> FunctionInfo | None:
    pattern = FUNC_PATTERN.get(language)
    if pattern is None:
        return None
    class_name = None
    class_pattern = CLASS_PATTERN.get(language)
    for idx in range(line_no - 1, -1, -1):
        match = pattern.match(lines[idx])
        if match:
            if class_pattern:
                for cidx in range(idx, -1, -1):
                    cmatch = class_pattern.match(lines[cidx])
                    if cmatch:
                        class_name = cmatch.group("name")
                        break
            return FunctionInfo(
                name=match.group("name"),
                start_line=idx + 1,
                signature=_signature(lines[idx]),
                class_name=class_name,
            )
    return None


def find_sink(alert_line: str) -> str | None:
    calls = SINK_CALL.findall(alert_line)
    preferred = [c for c in calls if c.split(".")[-1] in KNOWN_SINKS]
    if preferred:
        return preferred[-1]
    return calls[-1] if calls else None


def collect_imports(lines: list[str], upto: int, language: str) -> list[str]:
    imports: list[str] = []
    for line in lines[:upto]:
        stripped = line.strip()
        if language == "python" and (stripped.startswith("import ") or stripped.startswith("from ")):
            imports.append(stripped)
        elif language == "java" and stripped.startswith("import "):
            imports.append(stripped.rstrip(";"))
    return imports[-30:]


def collect_sources(lines: list[str], start: int, end: int, limit: int = 6) -> list[dict]:
    hits: list[dict] = []
    for idx in range(start, min(end, len(lines))):
        if SOURCE_HINT.search(lines[idx]):
            hits.append({"line": idx + 1, "code": lines[idx].strip()[:200]})
            if len(hits) >= limit:
                break
    return hits


PARAM_LIST = re.compile(r"\(([^)]*)\)")


def function_params(signature: str, language: str) -> list[str]:
    """从函数签名里取参数名（python 取 name: type 的 name，java 取 type name 的 name）。"""
    match = PARAM_LIST.search(signature)
    if not match:
        return []
    names: list[str] = []
    for raw in match.group(1).split(","):
        raw = raw.strip()
        if not raw or raw in {"self", "cls"}:
            continue
        if language == "python":
            name = raw.split(":")[0].split("=")[0].strip().lstrip("*")
        else:
            name = raw.split()[-1].replace("...", "").strip()
        if name and name.isidentifier():
            names.append(name)
    return names


def param_sources(function: FunctionInfo | None, language: str) -> list[dict]:
    if function is None:
        return []
    return [
        {"line": function.start_line, "kind": "parameter", "code": name}
        for name in function_params(function.signature, language)
    ]


def build_context(
    path: Path,
    line: int,
    radius: int = 8,
    rule_id: str = "",
    severity: str = "",
    message: str = "",
) -> CodeContext:
    lines = read_lines(path)
    if line < 1 or line > len(lines):
        raise ValueError(f"line {line} out of range 1..{len(lines)} for {path}")
    language = detect_language(path)
    context = CodeContext(
        file=str(path),
        language=language,
        line=line,
        rule_id=rule_id,
        severity=severity,
        message=message,
        sink=find_sink(lines[line - 1]),
        function=find_enclosing_function(lines, line, language),
        imports=collect_imports(lines, line - 1, language),
    )
    start = max(1, line - radius)
    end = min(len(lines), line + radius)
    func_start = context.function.start_line if context.function else start
    context.sources = param_sources(context.function, language) + collect_sources(lines, func_start, line)
    context.window = [start, end]
    width = len(str(end))
    context.code = "\n".join(f"{n:>{width}} | {lines[n - 1]}" for n in range(start, end + 1))
    return context


def markdown(ctx: CodeContext) -> str:
    fn = f"{ctx.function.name} (L{ctx.function.start_line})" if ctx.function else "N/A"
    cls = ctx.function.class_name if ctx.function and ctx.function.class_name else "N/A"
    parts = [
        f"### {Path(ctx.file).name}:{ctx.line} — {ctx.rule_id or 'manual'}",
        "",
        f"- file: `{ctx.file}`",
        f"- function: {fn}",
        f"- class: {cls}",
        f"- sink: `{ctx.sink}`",
        f"- sources: {len(ctx.sources)} 处",
        f"- message: {ctx.message or '-'}",
        "",
        "```" + (ctx.language if ctx.language != "other" else ""),
        ctx.code,
        "```",
    ]
    return "\n".join(parts)


def from_semgrep(semgrep_json: Path, radius: int, base: Path | None = None) -> list[CodeContext]:
    data = json.loads(semgrep_json.read_text(encoding="utf-8"))
    base = base or Path.cwd()
    contexts: list[CodeContext] = []
    for result in data.get("results", []):
        path = Path(result["path"])
        if not path.is_absolute():
            path = base / path
        try:
            contexts.append(
                build_context(
                    path,
                    int(result["start"]["line"]),
                    radius=radius,
                    rule_id=result.get("check_id", ""),
                    severity=str(result.get("extra", {}).get("severity", "")),
                    message=str(result.get("extra", {}).get("message", "")).strip(),
                )
            )
        except (OSError, ValueError, KeyError) as exc:  # 单条失败不影响整体
            print(f"[skip] {result.get('path')}: {exc}", file=sys.stderr)
    return contexts


class CodeContextExtractor:
    """面向 LLM 误报过滤的上下文抽取入口（便捷封装）。"""

    def __init__(self, radius: int = 8) -> None:
        self.radius = radius

    def extract(self, path: str | Path, line: int, **meta: str) -> CodeContext:
        return build_context(Path(path), line, radius=self.radius, **meta)

    def from_semgrep(self, semgrep_json: str | Path, base: Path | None = None) -> list[CodeContext]:
        return from_semgrep(Path(semgrep_json), self.radius, base)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="从扫描告警抽取结构化代码上下文")
    parser.add_argument("file", nargs="?", help="源码文件路径")
    parser.add_argument("line", nargs="?", type=int, help="告警行号 (1-based)")
    parser.add_argument("--semgrep-json", help="semgrep --json 输出文件")
    parser.add_argument("--radius", type=int, default=8, help="上下文窗口半径，默认 8 行")
    parser.add_argument("--rule-id", default="")
    parser.add_argument("--message", default="")
    parser.add_argument("--format", choices=["json", "markdown"], default="json")
    args = parser.parse_args(argv)

    extractor = CodeContextExtractor(radius=args.radius)
    if args.semgrep_json:
        contexts = extractor.from_semgrep(args.semgrep_json)
    elif args.file and args.line:
        contexts = [extractor.extract(args.file, args.line, rule_id=args.rule_id, message=args.message)]
    else:
        parser.print_help()
        return 2

    if args.format == "markdown":
        print("\n\n".join(markdown(ctx) for ctx in contexts))
    else:
        print(json.dumps([asdict(ctx) for ctx in contexts], ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
