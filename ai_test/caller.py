#!/usr/bin/env python3
"""caller.py — 读取 eBPF 观测 JSON 数据，调用大模型 API 生成系统性能分析报告。

用法:
  source venv/bin/activate
  python3 caller.py [report.json 路径] [-o 输出文件] [--dry-run]

API Key 配置:
  export DEEPSEEK_API_KEY="your-key-here"
  或在代码中修改 API_KEY 变量

依赖:
  pip install openai
"""

import os
import sys
import json
import argparse
from pathlib import Path
from openai import OpenAI

# API Key: 优先环境变量 > 外部文件 /api.txt > 内置默认值
def _load_api_key() -> str:
    key = os.environ.get("DEEPSEEK_API_KEY")
    if key:
        return key
    try:
        file = Path(__file__).parent / "api.txt"
        key = file.read_text(encoding="utf-8").strip()
        if key:
            return key
    except (FileNotFoundError, PermissionError):
        pass
    return "xxxxxxxx"

API_KEY = _load_api_key()
BASE_URL = "https://api.deepseek.com"
MODEL = "deepseek-v4-pro"

# ─── 系统分析专家 System Prompt ──────────────────────────────────────
SYSTEM_PROMPT = """\
你是一名资深的 Linux 系统性能分析专家，专精于 eBPF 性能观测与根因定位。
你的任务是根据 eBPF 采集的进程级 CPU 指标，生成一份专业的系统性能分析报告。

报告要求：
1. **总体评估**：用 2-3 句话概括当前系统的 CPU 健康状况
2. **TOP 进程分析**：对 CPU 占用最高的 3-5 个进程逐一分析，说明其行为特征
3. **异常根因判断**：如果存在异常进程，解释根因分类的依据（CPU 密集计算 / 
busy loop / 锁竞争 / 调度延迟）
4. **关联分析**：分析上下文切换、调度延迟、核间迁移、futex 等待之间的关联
5. **优化建议**：给出具体、可操作的优化建议（按优先级排序）
6. **风险提示**：指出需要人工进一步确认的信息（如符号解析不完整、栈采样缺失等）

输出格式：
- 使用 Markdown 排版
- 关键数值用粗体或表格呈现
- 建议部分用编号列表
- 不要重复原始 JSON 数据，只输出分析结果

只输出报告正文，不需要开头寒暄或结尾总结语。
不需要再最终生成的md文件添加思考过程文本，直接以# 系统分析报告作为.md 文件的开始
"""


def read_json(path: str) -> dict:
    """读取 JSON 文件，支持 encoding fallback。"""
    file_path = Path(path)
    if not file_path.is_file():
        sys.exit(f"找不到文件: {path}")
    for encoding in ("utf-8", "gbk", "latin-1"):
        try:
            return json.loads(file_path.read_text(encoding=encoding))
        except (UnicodeDecodeError, json.JSONDecodeError):
            continue
    sys.exit(f"无法解码文件（已尝试 utf-8 / gbk / latin-1）: {path}")


def summarize_data(data: dict) -> str:
    """从 JSON 中提取关键数据，整理成 AI 易于阅读的摘要。"""
    lines = []
    lines.append("## 采样信息")
    lines.append(f"- 时间: {data.get('timestamp', 'N/A')}")
    lines.append(f"- 采样窗口: {data.get('duration_s', 'N/A')} 秒")
    lines.append(f"- CPU 核心数: {data.get('ncpu', 'N/A')}")
    lines.append(f"- 系统负载 (1/5/15min): {data.get('system_load', 
                 {}).get('load1', 'N/A')} / "
                 f"{data.get('system_load', {}).get('load5', 'N/A')} / "
                 f"{data.get('system_load', {}).get('load15', 'N/A')}")
    runq = data.get('runq_depth', {})
    lines.append(f"- RunQ 深度 (running/blocked): {runq.get('running', 'N/A')} / {runq.get('blocked', 'N/A')}")
    lines.append(f"- schedstats 状态: {'启用' if data.get('schedstats_on') else '未启用（CPU 时间为挂墙时间，非精确核算值）'}")
    lines.append(f"- CPU 异常阈值: {data.get('cpu_threshold', 90)}%")
    lines.append(f"- 活跃进程数: {data.get('total_procs', 0)}")
    lines.append("")

    procs = data.get("top_procs", [])
    if not procs:
        lines.append("## 采样窗口内无活跃进程数据")
        return "\n".join(lines)

    # 统计摘要
    n_anomaly = sum(1 for p in procs if p.get("is_anomaly"))
    high_cpu = sum(1 for p in procs if p.get("cpu_pct", 0) > 50)
    lines.append("## 进程概况")
    lines.append(f"- TOP 进程数: {len(procs)}")
    lines.append(f"- 异常进程数: {n_anomaly}")
    lines.append(f"- CPU > 50% 进程数: {high_cpu}")
    lines.append("")

    # TOP 进程表格
    lines.append("## TOP 进程指标明细")
    lines.append("")
    lines.append("| PID | 进程名 | CPU% | 切换/min | 自愿切换 | 被动切换 | avg调度延迟(us) | max延迟(us) | 迁移次数 | futex等待 | 异常类型 |")
    lines.append("|-----|--------|------|----------|----------|----------|-----------------|-------------|----------|-----------|----------|")
    for p in procs:
        subtype = p.get("subtype", "") if p.get("is_anomaly") else "正常"
        if len(subtype) > 25:
            subtype = subtype[:25] + "..."
        lines.append(
            f"| {p['pid']} | {p['comm']} | {p['cpu_pct']:.1f} | {p['cswitch_per_min']:.0f} | "
            f"{p['cswitch_voluntary']} | {p['cswitch_involuntary']} | "
            f"{p['avg_sched_delay_us']:.1f} | {p['max_sched_delay_us']:.1f} | "
            f"{p['migrate_count']} | {p['futex_wait_count']} | {subtype} |"
        )
    lines.append("")

    # 异常进程详情
    if n_anomaly > 0:
        lines.append("## 异常进程诊断详情")
        lines.append("")
        for i, p in enumerate(procs):
            if not p.get("is_anomaly"):
                continue
            lines.append(f"### {i+1}. PID {p['pid']} — {p['comm']} ({p['subtype']})")
            lines.append(f"- CPU 占用: {p['cpu_pct']:.1f}%")
            lines.append(f"- 自愿切换占比: {p['voluntary_ratio']*100:.1f}%")
            lines.append(f"- 平均调度延迟: {p['avg_sched_delay_us']:.1f} us")
            if p.get("root_cause"):
                lines.append(f"- eBPF 判定根因: {p['root_cause']}")
            if p.get("suggestion"):
                lines.append(f"- eBPF 建议: {p['suggestion']}")
            lines.append("")

    return "\n".join(lines)


def build_user_prompt(data_summary: str) -> str:
    """构建用户消息 prompt。"""
    return f"""请根据以下 eBPF 实时采集的进程级 CPU 性能数据，生成一份系统性能分析报告。

采集数据如下：

{data_summary}

分析要点：
- 如果有异常进程，请重点分析其根因分类是否合理
- 如果调度延迟偏高，结合上下文切换数据判断是 CPU 争抢还是 I/O 等待导致
- 如果存在锁竞争特征（自愿切换多 + futex），给出排查建议
- 如果没有异常进程，简要说明系统运行状态即可
- 考虑 schedstats 是否启用对 CPU 计时精度的影响"""


def main():
    parser = argparse.ArgumentParser(
        description="eBPF 观测数据 AI 分析工具")
    parser.add_argument(
        "json_file", nargs="?", default="report.json",
        help="report.json 文件路径 (默认: report.json)")
    parser.add_argument(
        "-o", "--output", default="report.md",
        help="输出报告文件路径 (默认: report.md)")
    parser.add_argument(
        "--no-thinking", action="store_true",
        help="隐藏模型思考过程")
    parser.add_argument(
        "--dry-run", action="store_true",
        help="仅打印构建的 prompt，不调用 API")
    args = parser.parse_args()

    # 读取数据
    data = read_json(args.json_file)
    summary = summarize_data(data)

    # 构建消息
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": build_user_prompt(summary)},
    ]

    # 调用 API
    client = OpenAI(api_key=API_KEY, base_url=BASE_URL)

    if args.dry_run:
        print("=" * 60)
        print("  [ DRY RUN — System Prompt ]")
        print("=" * 60)
        print(SYSTEM_PROMPT)
        print("")
        print("=" * 60)
        print("  [ DRY RUN — User Prompt ]")
        print("=" * 60)
        print(messages[1]["content"])
        sys.exit(0)

    print(f"[*] 正在调用 {MODEL} 分析数据 ...\n", file=sys.stderr)

    response = client.chat.completions.create(
        model=MODEL,
        messages=messages,
        stream=False,
        reasoning_effort="high",
        extra_body={"thinking": {"type": "enabled"}},
    )

    # 输出
    out = open(args.output, "w") if args.output else None

    thinking = getattr(response.choices[0].message, "reasoning_content", None)
    answer = response.choices[0].message.content

    if thinking and not args.no_thinking:
        print("=" * 60, file=sys.stderr)
        print("  [ 模型思考过程 ]", file=sys.stderr)
        print("=" * 60, file=sys.stderr)
        print(thinking, file=sys.stderr)
        print("", file=sys.stderr)

    if out:
        out.write(answer)
        out.close()
        print(f"[*] 报告已保存到 {args.output}", file=sys.stderr)
    else:
        print(answer)


if __name__ == "__main__":
    main()
