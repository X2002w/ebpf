#!/usr/bin/env python3
"""db_loader.py — 从 SQLite 历史数据库加载 eBPF 观测数据。

将 findings 表中的行重新组装成与 JSON 报告相同的嵌套结构，
让下游 summarizer 无需感知数据源差异。

输出结构 (与 report/<module>.json 一致):
{
  "module": "io",
  "timestamp": "...",
  "duration_s": 2.0,
  "system": {...},
  "sections": [
    {"type": "diagnosis", "title": "...", "findings": [...]}
  ]
}
"""

import sqlite3
import sys
import json
from pathlib import Path
from typing import Optional


DEFAULT_DB = "report/eebpf.db"


def _open_db(db_path: str) -> Optional[sqlite3.Connection]:
	p = Path(db_path)
	if not p.is_file():
		return None
	try:
		conn = sqlite3.connect(f"file:{p}?mode=ro", uri=True)
		conn.row_factory = sqlite3.Row
		return conn
	except sqlite3.Error:
		return None


def _rows_to_findings(rows) -> list:
	"""把 findings 表的行转成 JSON findings 数组结构"""
	findings = []
	for r in rows:
		metrics = {}
		km_json = r["key_metrics_json"] or "{}"
		try:
			metrics = json.loads(km_json)
		except json.JSONDecodeError:
			pass

		evidence = []
		ev_json = r["evidence_json"] or "[]"
		try:
			evidence = json.loads(ev_json)
		except json.JSONDecodeError:
			pass

		findings.append({
			"target": r["target"] or "",
			"is_anomaly": bool(r["is_anomaly"]),
			"subtype": r["subtype"] or "",
			"root_cause": r["root_cause"] or "",
			"suggestion": r["suggestion"] or "",
			"time_window": r["time_window"] or "",
			"key_metrics": metrics,
			"evidence": evidence,
		})
	return findings


def _system_from_snapshots(conn, module: str) -> dict:
	"""从 snapshots 表取该模块最近一次的 system 段"""
	try:
		row = conn.execute(
			"SELECT system_json FROM snapshots WHERE module = ? "
			"ORDER BY timestamp DESC LIMIT 1",
			(module,)).fetchone()
	except sqlite3.Error:
		return {}
	if not row:
		return {}
	try:
		return json.loads(row["system_json"] or "{}")
	except json.JSONDecodeError:
		return {}


def _meta_from_reports(conn, module: str) -> dict:
	"""取该模块最近一次采样的元数据 (timestamp, duration_s)"""
	try:
		row = conn.execute(
			"SELECT timestamp, duration_s FROM reports WHERE module = ? "
			"ORDER BY timestamp DESC LIMIT 1",
			(module,)).fetchone()
	except sqlite3.Error:
		return {"timestamp": "", "duration_s": 0.0}
	if not row:
		return {"timestamp": "", "duration_s": 0.0}
	return {"timestamp": row["timestamp"], "duration_s": row["duration_s"]}


def _metric_history(conn: sqlite3.Connection, module: str, target: str,
                    metric_key: str, window_sec: int) -> list:
	"""查指定 (module, target, metric) 的历史值序列, 按时间正序"""
	try:
		rows = conn.execute(
			"SELECT CAST(m.value AS REAL) AS v, f.timestamp "
			"FROM findings f, json_each(f.key_metrics_json) m "
			"WHERE f.module = ? AND f.target = ? AND m.key = ? "
			"  AND f.timestamp >= datetime('now', ?) "
			"ORDER BY f.timestamp ASC",
			(module, target, metric_key, f"-{int(window_sec)} seconds")).fetchall()
	except sqlite3.Error:
		return []
	return [r["v"] for r in rows if r["v"] is not None]


def _first_numeric_metric(metrics: dict) -> Optional[str]:
	"""挑 key_metrics 里第一个能解析为数值的 key"""
	for k, v in metrics.items():
		try:
			float(str(v).rstrip("%").split()[0])
			return k
		except (ValueError, AttributeError):
			continue
	return None


def _baseline_stats(values: list) -> dict:
	"""Welford 算 mean/stddev, 与 C 侧 storage_get_metric_baseline 一致"""
	n = len(values)
	if n == 0:
		return {"mean": 0.0, "stddev": 0.0, "count": 0}
	mean = 0.0
	M2 = 0.0
	for i, x in enumerate(values, 1):
		delta = x - mean
		mean += delta / i
		M2 += delta * (x - mean)
	stddev = (M2 / (n - 1)) ** 0.5 if n > 1 else 0.0
	return {"mean": mean, "stddev": stddev, "count": n}


def attach_trends(conn: sqlite3.Connection, reports: dict,
                  window_sec: int = 3600) -> None:
	"""为每个异常 finding 附带代表性指标的历史趋势序列 + 基线统计"""
	for mod_name, data in reports.items():
		for sec in data.get("sections", []):
			if sec.get("type") != "diagnosis":
				continue
			for f in sec.get("findings", []):
				if not f.get("is_anomaly"):
					continue
				metrics = f.get("key_metrics", {})
				mk = _first_numeric_metric(metrics)
				if not mk:
					continue
				values = _metric_history(conn, mod_name, f["target"], mk, window_sec)
				if len(values) >= 2:
					f["_trend"] = {
						"key": mk,
						"values": values,
						"baseline": _baseline_stats(values),
					}


def load_module_from_db(conn: sqlite3.Connection, module: str,
                        window_sec: int = 3600) -> Optional[dict]:
	"""从 db 拉指定模块的窗口内 findings, 组装成 JSON 兼容结构"""
	try:
		rows = conn.execute(
			"SELECT target, is_anomaly, subtype, root_cause, suggestion, "
			"  time_window, key_metrics_json, evidence_json, timestamp "
			"FROM findings WHERE module = ? "
			"  AND timestamp >= datetime('now', ?) "
			"ORDER BY timestamp DESC",
			(module, f"-{int(window_sec)} seconds")).fetchall()
	except sqlite3.Error as e:
		print(f"[!] 查询 {module} findings 失败: {e}", file=sys.stderr)
		return None

	if not rows:
		return None

	meta = _meta_from_reports(conn, module)
	system = _system_from_snapshots(conn, module)
	findings = _rows_to_findings(rows)

	return {
		"module": module,
		"timestamp": meta["timestamp"],
		"duration_s": meta["duration_s"],
		"system": system,
		"sections": [
			{
				"type": "diagnosis",
				"title": f"{module} 历史诊断 (近 {window_sec}s)",
				"findings": findings,
			}
		],
	}


def load_reports_from_db(db_path: str, modules: list,
                         window_sec: int = 3600) -> dict:
	"""从 SQLite 加载多模块报告, 接口与 caller.load_reports 一致"""
	conn = _open_db(db_path)
	if conn is None:
		print(f"[!] 无法打开数据库: {db_path}", file=sys.stderr)
		return {}
	try:
		reports = {}
		for mod in modules:
			data = load_module_from_db(conn, mod, window_sec)
			if data:
				reports[mod] = data
			else:
				print(f"[!] db 中无 {mod} 模块数据 (窗口 {window_sec}s)",
				      file=sys.stderr)
		attach_trends(conn, reports, window_sec)
		return reports
	finally:
		conn.close()


def db_has_data(db_path: str) -> bool:
	"""检查 db 是否有 findings 数据, 用于 auto 模式判断"""
	conn = _open_db(db_path)
	if conn is None:
		return False
	try:
		row = conn.execute("SELECT COUNT(*) AS n FROM findings").fetchone()
		return row["n"] > 0
	except sqlite3.Error:
		return False
	finally:
		conn.close()


def load_correlations(window_s: int = 60) -> list:
	"""调用 ./eebpf correlate -j 拿关联结果, 按 reasoning 去重"""
	import subprocess
	try:
		r = subprocess.run(
			["./eebpf", "correlate", "-j", "--window", str(window_s)],
			capture_output=True, text=True, timeout=10)
	except (subprocess.SubprocessError, FileNotFoundError):
		return []
	if r.returncode != 0:
		return []
	try:
		data = json.loads(r.stdout)
	except json.JSONDecodeError:
		return []

	seen = set()
	deduped = []
	for item in data.get("results", []):
		# 按 reasoning 去重: 同一因果链只保留首条代表性结果
		key = item.get("reasoning", "")
		if key in seen:
			continue
		seen.add(key)
		deduped.append(item)
	return deduped
