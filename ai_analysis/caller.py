#!/usr/bin/env python3
"""caller.py — 多模块 eBPF 观测数据联合 AI 诊断分析。

读取 ai_report/ 目录下模块 JSON，结合系统硬件信息，调用 DeepSeek API 生成跨模块关联诊断报告。

用法:
  source ai_analysis/venv/bin/activate
  python3 ai_analysis/caller.py [report_dir] [-o 输出] [-m 模块列表] [--dry-run]

依赖:
  pip install openai
"""

import os
import sys
import json
import argparse
from pathlib import Path

# 将当前目录加入路径以便导入 sys_message
sys.path.insert(0, str(Path(__file__).parent))
from sys_message import collect_all, to_text as sys_to_text
from openai import OpenAI


# API 配置（优先环境变量 > api.txt > api_config.json > 默认值）

def _load_api_config() -> dict:
	"""加载 API 配置，优先级: 环境变量 > api.txt > api_config.json > 默认值"""
	defaults = {
		"api_key": "sk-xxxxxxxx",
		"base_url": "https://api.deepseek.com",
		"model": "deepseek-v4-pro",
	}
	config = defaults.copy()

	# 1. JSON 配置文件（公共模板）
	try:
		file = Path(__file__).parent / "api_config.json"
		if file.is_file():
			with open(file, encoding="utf-8") as f:
				cfg = json.load(f)
			config.update(cfg)
	except (FileNotFoundError, PermissionError, json.JSONDecodeError):
		pass

	# 2. 纯文本 key 文件（本地测试，gitignore 保护）
	try:
		key_file = Path(__file__).parent / "api.txt"
		if key_file.is_file():
			key = key_file.read_text(encoding="utf-8").strip()
			if key:
				config["api_key"] = key
	except (FileNotFoundError, PermissionError):
		pass

	# 3. 环境变量覆盖（最高优先级）
	env_key = os.environ.get("DEEPSEEK_API_KEY")
	if env_key:
		config["api_key"] = env_key
	env_url = os.environ.get("DEEPSEEK_BASE_URL")
	if env_url:
		config["base_url"] = env_url
	env_model = os.environ.get("DEEPSEEK_MODEL")
	if env_model:
		config["model"] = env_model

	return config

_api_config = _load_api_config()
API_KEY = _api_config["api_key"]
BASE_URL = _api_config["base_url"]
MODEL = _api_config["model"]

# System Prompt（从外部文件加载，便于独立编辑）

def _load_system_prompt() -> str:
	prompt_file = Path(__file__).parent / "system_prompt.md"
	if prompt_file.is_file():
		return prompt_file.read_text(encoding="utf-8").strip()
	return "你是一名资深的 Linux 系统性能分析专家，请根据 eBPF 采集数据生成诊断报告。"

SYSTEM_PROMPT = _load_system_prompt()

# 表格行截断

MAX_TABLE_ROWS = 10  # 每个表格最多保留的行数，控制 token 成本


def _trim_rows(rows, max_rows=MAX_TABLE_ROWS):
	if not rows:
		return rows
	if len(rows) <= max_rows:
		return rows
	trimmed = rows[:max_rows]
	col_count = len(trimmed[0])
	placeholder = [f"... 共 {len(rows)} 行，已截断" ] + ["..." for _ in range(col_count - 1)]
	return trimmed + [placeholder]


# JSON 读取

def read_json(path: str) -> dict:
	file_path = Path(path)
	if not file_path.is_file():
		return None
	for encoding in ("utf-8", "gbk", "latin-1"):
		try:
			return json.loads(file_path.read_text(encoding=encoding))
		except (UnicodeDecodeError, json.JSONDecodeError):
			continue
	return None


def load_reports(report_dir: str, modules: list = None) -> dict:
	all_modules = ["cpu", "io", "mem", "lock", "hot"]
	if modules:
		all_modules = [m for m in modules if m in all_modules]
	reports = {}
	base = Path(report_dir)
	for mod in all_modules:
		path = base / f"{mod}.json"
		data = read_json(str(path))
		if data:
			reports[mod] = data
	return reports


# 各模块数据摘要

def _fmt_table(title, columns, rows):
	lines = [f"### {title}", ""]
	if not rows:
		lines.append("(无数据)")
		lines.append("")
		return lines

	header = "| " + " | ".join(str(c) for c in columns) + " |"
	sep = "|" + "|".join("-----" for _ in columns) + "|"
	lines.append(header)
	lines.append(sep)
	for row in _trim_rows(rows):
		lines.append("| " + " | ".join(str(c) for c in row) + " |")
	lines.append("")
	return lines


def _fmt_kv(title, rows):
	lines = [f"### {title}", ""]
	if not rows:
		lines.append("(无数据)")
		lines.append("")
		return lines
	for r in rows:
		lines.append(f"- {r['key']}: {r['value']}")
	lines.append("")
	return lines


def _fmt_findings(findings):
	lines = []
	anomalies = [f for f in findings if f.get("is_anomaly")]
	warnings = [f for f in findings if not f.get("is_anomaly")]

	if anomalies:
		lines.append("#### 异常项")
		lines.append("")
		for i, f in enumerate(anomalies):
			lines.append(f"**{i+1}. {f.get('target', '(未知)')}** — {f.get('subtype', '')}")
			if f.get("root_cause"):
				lines.append(f"- 根因: {f['root_cause']}")
			if f.get("suggestion"):
				lines.append(f"- 建议: {f['suggestion']}")
			if f.get("evidence"):
				for e in f["evidence"]:
					lines.append(f"- 证据: {e}")
			lines.append("")

	if warnings:
		lines.append("#### 注意事项")
		lines.append("")
		for i, f in enumerate(warnings):
			lines.append(f"**{i+1}. {f.get('target', '(未知)')}** — {f.get('subtype', '')}")
			if f.get("root_cause"):
				lines.append(f"- 说明: {f['root_cause']}")
			lines.append("")

	return lines


def _get_sections(data):
	tables, kvs, diagnosis = [], [], []
	for sec in data.get("sections", []):
		t = sec.get("type")
		if t == "table":
			tables.append(sec)
		elif t == "kv":
			kvs.append(sec)
		elif t == "diagnosis":
			diagnosis.append(sec)
	return tables, kvs, diagnosis


def _anomaly_stats(reports: dict) -> str:
	lines = ["## 异常概况", ""]
	for mod_name, data in reports.items():
		n_anom, n_warn = 0, 0
		for sec in data.get("sections", []):
			if sec.get("type") == "diagnosis":
				for f in sec.get("findings", []):
					if f.get("is_anomaly"):
						n_anom += 1
					else:
						n_warn += 1
		if n_anom > 0 or n_warn > 0:
			lines.append(f"- {mod_name}: {n_anom} 异常, {n_warn} 注意")
		else:
			lines.append(f"- {mod_name}: 正常")
	lines.append("")
	return "\n".join(lines)


def summarize_cpu(data: dict) -> str:
	lines = ["## CPU 模块", ""]
	sysinfo = data.get("system", {})
	lines.append(f"- 核心数: {sysinfo.get('CPU 核心数', 'N/A')}, 负载: {sysinfo.get('系统负载 (1m/5m/15m)', 'N/A')}")
	lines.append(f"- RunQ: {sysinfo.get('RunQ 深度 (瞬时)', 'N/A')}, schedstats: {sysinfo.get('schedstats', 'N/A')}")
	lines.append("")

	tables, _, diagnosis = _get_sections(data)
	for tab in tables:
		lines.extend(_fmt_table(tab["title"], tab["columns"], tab.get("rows", [])))
	for diag in diagnosis:
		lines.append(f"### {diag['title']}")
		lines.append("")
		findings = diag.get("findings", [])
		if findings:
			lines.extend(_fmt_findings(findings))
		else:
			lines.append("无异常进程检测到")
			lines.append("")
	return "\n".join(lines)


def summarize_io(data: dict) -> str:
	lines = ["## I/O 模块", ""]
	sysinfo = data.get("system", {})
	lines.append(f"- 活跃设备: {sysinfo.get('活跃块设备数', 'N/A')}, 负载: {sysinfo.get('系统负载 (1m/5m/15m)', 'N/A')}")
	lines.append("")

	tables, kvs, diagnosis = _get_sections(data)
	for kv in kvs:
		lines.extend(_fmt_kv(kv["title"], kv.get("rows", [])))
	for tab in tables:
		lines.extend(_fmt_table(tab["title"], tab["columns"], tab.get("rows", [])))
	for diag in diagnosis:
		lines.append(f"### {diag['title']}")
		lines.append("")
		findings = diag.get("findings", [])
		if findings:
			lines.extend(_fmt_findings(findings))
		else:
			lines.append("(无诊断结论)")
			lines.append("")
	return "\n".join(lines)


def summarize_mem(data: dict) -> str:
	lines = ["## 内存模块", ""]
	sysinfo = data.get("system", {})
	lines.append(f"- {sysinfo.get('总内存', 'N/A')}, 可用 {sysinfo.get('可用内存', 'N/A')}, Swap {sysinfo.get('Swap', 'N/A')}")
	lines.append("")

	tables, kvs, diagnosis = _get_sections(data)
	for kv in kvs:
		lines.extend(_fmt_kv(kv["title"], kv.get("rows", [])))
	for tab in tables:
		lines.extend(_fmt_table(tab["title"], tab["columns"], tab.get("rows", [])))
	for diag in diagnosis:
		lines.append(f"### {diag['title']}")
		lines.append("")
		findings = diag.get("findings", [])
		if findings:
			lines.extend(_fmt_findings(findings))
		else:
			lines.append("(无诊断结论)")
			lines.append("")
	return "\n".join(lines)


def summarize_hot(data: dict) -> str:
	lines = ["## 系统调用 (syscall) 模块", ""]
	sysinfo = data.get("system", {})
	lines.append(f"- 总调用: {sysinfo.get('系统调用总数', 'N/A')}, 总耗时: {sysinfo.get('总耗时', 'N/A')}, 错误: {sysinfo.get('错误数', 'N/A')}")
	lines.append("")

	tables, _, diagnosis = _get_sections(data)
	for tab in tables:
		lines.extend(_fmt_table(tab["title"], tab["columns"], tab.get("rows", [])))
	for diag in diagnosis:
		lines.append(f"### {diag['title']}")
		lines.append("")
		findings = diag.get("findings", [])
		if findings:
			lines.extend(_fmt_findings(findings))
		else:
			lines.append("(无诊断结论)")
			lines.append("")
	return "\n".join(lines)


def summarize_lock(data: dict) -> str:
	lines = ["## 锁竞争模块", ""]
	sysinfo = data.get("system", {})
	if sysinfo:
		for k, v in sysinfo.items():
			lines.append(f"- {k}: {v}")
		lines.append("")

	tables, _, diagnosis = _get_sections(data)
	for tab in tables:
		lines.extend(_fmt_table(tab["title"], tab["columns"], tab.get("rows", [])))
	for diag in diagnosis:
		lines.append(f"### {diag['title']}")
		lines.append("")
		findings = diag.get("findings", [])
		if findings:
			lines.extend(_fmt_findings(findings))
		else:
			lines.append("(无诊断结论)")
			lines.append("")
	return "\n".join(lines)


SUMMARIZERS = {
	"cpu": summarize_cpu,
	"io": summarize_io,
	"mem": summarize_mem,
	"hot": summarize_hot,
	"lock": summarize_lock,
}

MODULE_NAMES = {
	"cpu": "CPU",
	"io": "I/O",
	"mem": "内存",
	"lock": "锁竞争",
	"hot": "系统调用",
}


# 构建 Prompt

def build_combined_summary(reports: dict, modules: list) -> str:
	parts = []

	parts.append("# eBPF 采样数据汇总")
	parts.append("")
	parts.append("## 已加载模块")
	for mod in modules:
		if mod in reports:
			parts.append(f"- {MODULE_NAMES.get(mod, mod)}: 已加载")
	parts.append("")

	parts.append(_anomaly_stats(reports))

	for mod in modules:
		if mod in reports:
			summarizer = SUMMARIZERS.get(mod)
			if summarizer:
				parts.append(summarizer(reports[mod]))
				parts.append("")

	return "\n".join(parts)


def build_user_prompt(data_summary: str, sys_text: str, modules: list) -> str:
	mod_list = "、".join(MODULE_NAMES.get(m, m) for m in modules)
	return f"""请根据以下 eBPF 采集的 {mod_list} 数据和系统硬件信息，生成系统性能诊断报告。

{data_summary}

{sys_text}

分析要点：
- 评估各模块独立状态，判断是否存在异常
- 重点进行跨模块关联分析，寻找异常之间的因果关系
- 如果多个模块同时异常，推断根因链（最可能的因果顺序）
- 评估系统硬件环境是否构成瓶颈
- 区分真实异常（异常项）和低风险提示（注意事项），优先分析异常项"""


# 主入口

def main():
	parser = argparse.ArgumentParser(
		description="eBPF 多模块联合 AI 诊断分析")
	parser.add_argument(
		"report_dir", nargs="?", default="ai_report",
		help="report 目录路径 (默认: ai_report/)")
	parser.add_argument(
		"-o", "--output", default="ai_report/ai_diagnosis.md",
		help="输出报告文件路径 (默认: ai_report/ai_diagnosis.md)")
	parser.add_argument(
		"-m", "--modules", default="cpu,io,mem,hot,lock",
		help="分析模块列表，逗号分隔 (默认: cpu,io,mem,hot,lock)")
	parser.add_argument(
		"--no-thinking", action="store_true",
		help="隐藏模型思考过程")
	parser.add_argument(
		"--dry-run", action="store_true",
		help="仅打印构建的 prompt，不调用 API")
	args = parser.parse_args()

	# 解析模块列表
	wanted = [m.strip() for m in args.modules.split(",") if m.strip()]
	reports = load_reports(args.report_dir, wanted)
	if not reports:
		sys.exit(f"在 {args.report_dir}/ 下未找到指定模块的 JSON 文件: {args.modules}")

	loaded_mods = [m for m in wanted if m in reports]
	skipped = [m for m in wanted if m not in reports]
	print(f"[*] 已加载 {len(loaded_mods)} 个模块: {', '.join(loaded_mods)}", file=sys.stderr)
	if skipped:
		print(f"[!] 未找到: {', '.join(skipped)}", file=sys.stderr)

	# 构建摘要
	data_summary = build_combined_summary(reports, loaded_mods)
	sys_data = collect_all()
	sys_text = sys_to_text(sys_data)

	# 构建消息
	messages = [
		{"role": "system", "content": SYSTEM_PROMPT},
		{"role": "user", "content": build_user_prompt(data_summary, sys_text, loaded_mods)},
	]

	if args.dry_run:
		print("=" * 60)
		print("  [ DRY RUN — System Prompt ]")
		print("=" * 60)
		print(SYSTEM_PROMPT)
		print("")
		print("=" * 60)
		print("  [ DRY RUN — System Info ]")
		print("=" * 60)
		print(sys_text)
		print("")
		print("=" * 60)
		print("  [ DRY RUN — User Prompt ]")
		print("=" * 60)
		print(messages[1]["content"])
		sys.exit(0)

	# 调用 API
	client = OpenAI(api_key=API_KEY, base_url=BASE_URL)
	print(f"[*] 正在调用 {MODEL} 分析 {len(loaded_mods)} 个模块 ...\n", file=sys.stderr)

	response = client.chat.completions.create(
		model=MODEL,
		messages=messages,
		stream=False,
		reasoning_effort="high",
		extra_body={"thinking": {"type": "enabled"}},
	)

	thinking = getattr(response.choices[0].message, "reasoning_content", None)
	answer = response.choices[0].message.content

	if thinking and not args.no_thinking:
		print("=" * 60, file=sys.stderr)
		print("  [ 模型思考过程 ]", file=sys.stderr)
		print("=" * 60, file=sys.stderr)
		print(thinking, file=sys.stderr)
		print("", file=sys.stderr)

	if args.output:
		out_dir = os.path.dirname(args.output)
		if out_dir:
			os.makedirs(out_dir, exist_ok=True)
		out = open(args.output, "w")
		out.write(answer)
		out.close()
		print(f"[*] 报告已保存到 {args.output}", file=sys.stderr)
	else:
		print(answer)


if __name__ == "__main__":
	main()
