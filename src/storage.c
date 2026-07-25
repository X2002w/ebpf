// storage.c — SQLite 历史数据存储
//
// JSON 解析全部走 SQLite JSON1 (json_extract / json_each),
// 不再手写 tokenizer — 原始 JSON 整体绑定到 SQL 参数后用 path 表达式取值

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <sys/stat.h>
#include "sqlite3.h"
#include "../include/storage.h"
#include "../include/config.h"

static sqlite3 *g_db = NULL;

// 确保目录存在，不存在则创建
static int ensure_dir(const char *path)
{
	struct stat st;
	if (stat(path, &st) != 0) {
		if (mkdir(path, 0755) != 0)
			return -1;
	}
	return 0;
}


int storage_init(const char *db_path)
{
	if (!g_cfg.storage_enabled) return 0;
	if (g_db) return 0;

	if (ensure_dir("report") != 0) {
		fprintf(stderr, "[!] 无法创建 report 目录\n");
		return -1;
	}
	if (sqlite3_open(db_path, &g_db) != SQLITE_OK) {
		fprintf(stderr, "[!] 无法打开数据库 %s: %s\n",
			db_path, sqlite3_errmsg(g_db));
		sqlite3_close(g_db);
		g_db = NULL;
		return -1;
	}

	char *err = NULL;
	if (sqlite3_exec(g_db, "PRAGMA journal_mode=WAL", NULL, NULL, &err) != SQLITE_OK) {
		fprintf(stderr, "[!] WAL 模式设置失败: %s\n", err);
		sqlite3_free(err);
	}
	if (sqlite3_exec(g_db, "PRAGMA foreign_keys=ON", NULL, NULL, &err) != SQLITE_OK) {
		fprintf(stderr, "[!] foreign_keys 设置失败: %s\n", err);
		sqlite3_free(err);
	}

	const char *ddl =
		"CREATE TABLE IF NOT EXISTS reports ("
		"  id INTEGER PRIMARY KEY AUTOINCREMENT,"
		"  module TEXT NOT NULL, timestamp TEXT NOT NULL,"
		"  duration_s REAL NOT NULL, raw_json TEXT NOT NULL,"
		"  created_at TEXT NOT NULL DEFAULT (datetime('now'))"
		");"
		"CREATE TABLE IF NOT EXISTS findings ("
		"  id INTEGER PRIMARY KEY AUTOINCREMENT,"
		"  report_id INTEGER NOT NULL REFERENCES reports(id) ON DELETE CASCADE,"
		"  module TEXT NOT NULL, target TEXT NOT NULL,"
		"  is_anomaly INTEGER NOT NULL DEFAULT 0,"
		"  subtype TEXT NOT NULL, root_cause TEXT NOT NULL,"
		"  suggestion TEXT NOT NULL, time_window TEXT NOT NULL,"
		"  key_metrics_json TEXT NOT NULL DEFAULT '{}',"
		"  evidence_json TEXT NOT NULL DEFAULT '[]',"
		"  timestamp TEXT NOT NULL,"
		"  created_at TEXT NOT NULL DEFAULT (datetime('now'))"
		");"
		"CREATE TABLE IF NOT EXISTS snapshots ("
		"  id INTEGER PRIMARY KEY AUTOINCREMENT,"
		"  report_id INTEGER NOT NULL REFERENCES reports(id) ON DELETE CASCADE,"
		"  module TEXT NOT NULL, timestamp TEXT NOT NULL,"
		"  system_json TEXT NOT NULL DEFAULT '{}',"
		"  created_at TEXT NOT NULL DEFAULT (datetime('now'))"
		");"
		"CREATE INDEX IF NOT EXISTS idx_reports_module_time ON reports(module, timestamp);"
		"CREATE INDEX IF NOT EXISTS idx_findings_module_time ON findings(module, timestamp);"
		"CREATE INDEX IF NOT EXISTS idx_findings_subtype ON findings(module, subtype);"
		"CREATE INDEX IF NOT EXISTS idx_snapshots_module_time ON snapshots(module, timestamp);";

	if (sqlite3_exec(g_db, ddl, NULL, NULL, &err) != SQLITE_OK) {
		fprintf(stderr, "[!] 建表失败: %s\n", err);
		sqlite3_free(err);
		return -1;
	}
	return 0;
}

void storage_close(void)
{
	if (g_db) { sqlite3_close(g_db); g_db = NULL; }
}

int storage_is_enabled(void)
{
	return g_cfg.storage_enabled && g_db != NULL;
}

// 从 key_metrics_json (JSON 对象) 填充 finding_t.metrics[]
// 走 SQLite json_each — json 参数按 SQLITE_TRANSIENT 拷贝, 可立即释放
static void fill_metrics_from_json(const char *json, finding_t *fd)
{
	if (!json || !*json) return;
	sqlite3_stmt *m;
	if (sqlite3_prepare_v2(g_db,
		"SELECT key, value FROM json_each(?)", -1, &m, NULL) != SQLITE_OK)
		return;
	sqlite3_bind_text(m, 1, json, -1, SQLITE_TRANSIENT);
	while (sqlite3_step(m) == SQLITE_ROW && fd->n_metrics < STORAGE_MAX_METRICS) {
		const char *k = (const char*)sqlite3_column_text(m, 0);
		const char *v = (const char*)sqlite3_column_text(m, 1);
		if (!k || !v) continue;
		snprintf(fd->metrics[fd->n_metrics].key, STORAGE_MAX_STR, "%s", k);
		snprintf(fd->metrics[fd->n_metrics].val, STORAGE_MAX_STR, "%s", v);
		fd->n_metrics++;
	}
	sqlite3_finalize(m);
}

// 从 evidence_json (JSON 数组) 填充 finding_t.evidence[]
static void fill_evidence_from_json(const char *json, finding_t *fd)
{
	if (!json || !*json) return;
	sqlite3_stmt *e;
	if (sqlite3_prepare_v2(g_db,
		"SELECT value FROM json_each(?)", -1, &e, NULL) != SQLITE_OK)
		return;
	sqlite3_bind_text(e, 1, json, -1, SQLITE_TRANSIENT);
	while (sqlite3_step(e) == SQLITE_ROW && fd->n_evidence < STORAGE_MAX_EVIDENCE) {
		const char *v = (const char*)sqlite3_column_text(e, 0);
		if (!v) continue;
		snprintf(fd->evidence[fd->n_evidence], STORAGE_MAX_STR * 2, "%s", v);
		fd->n_evidence++;
	}
	sqlite3_finalize(e);
}

// 读取整个文件到 malloc 缓冲区, 调用方负责 free
static char *read_file_all(const char *path)
{
	FILE *f = fopen(path, "r");
	if (!f) return NULL;
	fseek(f, 0, SEEK_END);
	long sz = ftell(f);
	rewind(f);
	char *buf = malloc(sz + 1);
	if (!buf) { fclose(f); return NULL; }
	size_t rd = fread(buf, 1, sz, f);
	fclose(f);
	buf[rd] = '\0';
	return buf;
}

int storage_save_from_json(const char *module, const char *json_path)
{
	if (!storage_is_enabled()) return 0;

	char *raw = read_file_all(json_path);
	if (!raw) {
		fprintf(stderr, "[!] 无法读取 %s\n", json_path);
		return -1;
	}

	char *err = NULL;
	if (sqlite3_exec(g_db, "BEGIN TRANSACTION", NULL, NULL, &err) != SQLITE_OK) {
		fprintf(stderr, "[!] BEGIN TRANSACTION 失败: %s\n", err);
		sqlite3_free(err);
		free(raw);
		return -1;
	}

	// reports: 顶层字段直接从原始 JSON path 取值
	sqlite3_stmt *s;
	if (sqlite3_prepare_v2(g_db,
		"INSERT INTO reports (module, timestamp, duration_s, raw_json)"
		" VALUES (json_extract(?, '$.module'), json_extract(?, '$.timestamp'),"
		"         json_extract(?, '$.duration_s'), ?)", -1, &s, NULL) != SQLITE_OK) {
		fprintf(stderr, "[!] 预编译 reports INSERT 失败: %s\n", sqlite3_errmsg(g_db));
		goto fail;
	}
	// 三个 path 参数 + raw_json 都绑定同一份原文
	sqlite3_bind_text(s, 1, raw, -1, SQLITE_STATIC);
	sqlite3_bind_text(s, 2, raw, -1, SQLITE_STATIC);
	sqlite3_bind_text(s, 3, raw, -1, SQLITE_STATIC);
	sqlite3_bind_text(s, 4, raw, -1, SQLITE_STATIC);
	if (sqlite3_step(s) != SQLITE_DONE) {
		fprintf(stderr, "[!] INSERT reports 失败: %s\n", sqlite3_errmsg(g_db));
		sqlite3_finalize(s);
		goto fail;
	}
	sqlite3_finalize(s);

	long long rid = sqlite3_last_insert_rowid(g_db);

	// findings: 一条 SQL 拉平 sections[type=diagnosis].findings[]
	// key_metrics/evidence 直接存 json_extract 返回的 JSON 文本, 避免 C 侧再序列化
	if (sqlite3_prepare_v2(g_db,
		"INSERT INTO findings (report_id, module, target, is_anomaly,"
		"  subtype, root_cause, suggestion, time_window,"
		"  key_metrics_json, evidence_json, timestamp)"
		" SELECT ?, json_extract(?, '$.module'),"
		"   json_extract(f.value, '$.target'),"
		"   COALESCE(json_extract(f.value, '$.is_anomaly'), 0),"
		"   COALESCE(json_extract(f.value, '$.subtype'), ''),"
		"   COALESCE(json_extract(f.value, '$.root_cause'), ''),"
		"   COALESCE(json_extract(f.value, '$.suggestion'), ''),"
		"   COALESCE(json_extract(f.value, '$.time_window'), ''),"
		"   COALESCE(json_extract(f.value, '$.key_metrics'), '{}'),"
		"   COALESCE(json_extract(f.value, '$.evidence'), '[]'),"
		"   json_extract(?, '$.timestamp')"
		" FROM json_each(?, '$.sections') s, json_each(s.value, '$.findings') f"
		" WHERE json_extract(s.value, '$.type') = 'diagnosis'",
		-1, &s, NULL) != SQLITE_OK) {
		fprintf(stderr, "[!] 预编译 findings INSERT 失败: %s\n", sqlite3_errmsg(g_db));
		goto fail;
	}
	sqlite3_bind_int64(s, 1, rid);
	sqlite3_bind_text(s, 2, raw, -1, SQLITE_STATIC);
	sqlite3_bind_text(s, 3, raw, -1, SQLITE_STATIC);
	sqlite3_bind_text(s, 4, raw, -1, SQLITE_STATIC);
	if (sqlite3_step(s) != SQLITE_DONE) {
		fprintf(stderr, "[!] INSERT findings 失败: %s\n", sqlite3_errmsg(g_db));
		sqlite3_finalize(s);
		goto fail;
	}
	sqlite3_finalize(s);

	// snapshots: system 段原样存为 JSON 文本
	if (sqlite3_prepare_v2(g_db,
		"INSERT INTO snapshots (report_id, module, timestamp, system_json)"
		" VALUES (?, json_extract(?, '$.module'), json_extract(?, '$.timestamp'),"
		"         COALESCE(json_extract(?, '$.system'), '{}'))",
		-1, &s, NULL) != SQLITE_OK) {
		fprintf(stderr, "[!] 预编译 snapshots INSERT 失败: %s\n", sqlite3_errmsg(g_db));
		goto fail;
	}
	sqlite3_bind_int64(s, 1, rid);
	sqlite3_bind_text(s, 2, raw, -1, SQLITE_STATIC);
	sqlite3_bind_text(s, 3, raw, -1, SQLITE_STATIC);
	sqlite3_bind_text(s, 4, raw, -1, SQLITE_STATIC);
	if (sqlite3_step(s) != SQLITE_DONE) {
		fprintf(stderr, "[!] INSERT snapshots 失败: %s\n", sqlite3_errmsg(g_db));
		sqlite3_finalize(s);
		goto fail;
	}
	sqlite3_finalize(s);

	free(raw);
	if (sqlite3_exec(g_db, "COMMIT", NULL, NULL, &err) != SQLITE_OK) {
		fprintf(stderr, "[!] COMMIT 失败: %s\n", err);
		sqlite3_free(err);
		return -1;
	}
	return 0;

fail:
	free(raw);
	sqlite3_exec(g_db, "ROLLBACK", NULL, NULL, NULL);
	(void)module;
	return -1;
}

int storage_parse_findings_json(const char *json_path, finding_t *out, int max)
{
	if (!g_db) return 0;
	char *raw = read_file_all(json_path);
	if (!raw) return 0;

	sqlite3_stmt *s;
	if (sqlite3_prepare_v2(g_db,
		"SELECT json_extract(f.value, '$.target'),"
		"  COALESCE(json_extract(f.value, '$.is_anomaly'), 0),"
		"  COALESCE(json_extract(f.value, '$.subtype'), ''),"
		"  COALESCE(json_extract(f.value, '$.root_cause'), ''),"
		"  COALESCE(json_extract(f.value, '$.suggestion'), ''),"
		"  COALESCE(json_extract(f.value, '$.time_window'), ''),"
		"  COALESCE(json_extract(f.value, '$.key_metrics'), '{}'),"
		"  COALESCE(json_extract(f.value, '$.evidence'), '[]')"
		" FROM json_each(?, '$.sections') s, json_each(s.value, '$.findings') f"
		" WHERE json_extract(s.value, '$.type') = 'diagnosis' LIMIT ?",
		-1, &s, NULL) != SQLITE_OK) {
		free(raw);
		return 0;
	}
	sqlite3_bind_text(s, 1, raw, -1, SQLITE_TRANSIENT);
	sqlite3_bind_int(s, 2, max);

	int n = 0;
	while (sqlite3_step(s) == SQLITE_ROW && n < max) {
		finding_t *fd = &out[n];
		memset(fd, 0, sizeof(*fd));
		snprintf(fd->target, STORAGE_MAX_STR, "%s", sqlite3_column_text(s, 0));
		fd->is_anomaly = sqlite3_column_int(s, 1);
		snprintf(fd->subtype, STORAGE_MAX_STR, "%s", sqlite3_column_text(s, 2));
		snprintf(fd->root_cause, STORAGE_MAX_LONG_STR, "%s", sqlite3_column_text(s, 3));
		snprintf(fd->suggestion, STORAGE_MAX_LONG_STR, "%s", sqlite3_column_text(s, 4));
		snprintf(fd->time_window, STORAGE_MAX_STR, "%s", sqlite3_column_text(s, 5));
		fill_metrics_from_json((const char*)sqlite3_column_text(s, 6), fd);
		fill_evidence_from_json((const char*)sqlite3_column_text(s, 7), fd);
		n++;
	}
	sqlite3_finalize(s);
	free(raw);
	return n;
}

int storage_get_recent_findings(const char *module, double within_sec,
				finding_t *out, int max)
{
	if (!storage_is_enabled()) return 0;

	char sql[512];
	snprintf(sql, sizeof(sql),
		"SELECT target, is_anomaly, subtype, root_cause, suggestion,"
		"  time_window, key_metrics_json, evidence_json, timestamp"
		" FROM findings WHERE module = ?"
		"  AND timestamp >= datetime('now', '-%d seconds')"
		" ORDER BY timestamp DESC LIMIT %d",
		(int)within_sec, max);

	sqlite3_stmt *s;
	sqlite3_prepare_v2(g_db, sql, -1, &s, NULL);
	sqlite3_bind_text(s, 1, module, -1, SQLITE_STATIC);

	int n = 0;
	while (sqlite3_step(s) == SQLITE_ROW && n < max) {
		finding_t *fd = &out[n];
		memset(fd, 0, sizeof(*fd));
		snprintf(fd->target, STORAGE_MAX_STR, "%s", sqlite3_column_text(s, 0));
		fd->is_anomaly = sqlite3_column_int(s, 1);
		snprintf(fd->subtype, STORAGE_MAX_STR, "%s", sqlite3_column_text(s, 2));
		snprintf(fd->root_cause, STORAGE_MAX_LONG_STR, "%s", sqlite3_column_text(s, 3));
		snprintf(fd->suggestion, STORAGE_MAX_LONG_STR, "%s", sqlite3_column_text(s, 4));
		snprintf(fd->time_window, STORAGE_MAX_STR, "%s", sqlite3_column_text(s, 5));
		snprintf(fd->timestamp, sizeof(fd->timestamp), "%s", sqlite3_column_text(s, 8));
		fill_metrics_from_json((const char*)sqlite3_column_text(s, 6), fd);
		fill_evidence_from_json((const char*)sqlite3_column_text(s, 7), fd);
		n++;
	}
	sqlite3_finalize(s);
	return n;
}

int storage_get_timeline(const char *module, int limit,
			 timeline_entry_t *out, int max)
{
	if (!storage_is_enabled()) return 0;
	if (limit > max) limit = max;

	char sql[512];
	snprintf(sql, sizeof(sql),
		"SELECT r.timestamp, r.duration_s,"
		"  COUNT(CASE WHEN f.is_anomaly=1 THEN 1 END)"
		" FROM reports r LEFT JOIN findings f ON f.report_id = r.id"
		" WHERE r.module = ? GROUP BY r.id"
		" ORDER BY r.timestamp DESC LIMIT %d", limit);

	sqlite3_stmt *s;
	sqlite3_prepare_v2(g_db, sql, -1, &s, NULL);
	sqlite3_bind_text(s, 1, module, -1, SQLITE_STATIC);

	int n = 0;
	while (sqlite3_step(s) == SQLITE_ROW && n < max) {
		snprintf(out[n].timestamp, sizeof(out[n].timestamp), "%s",
			 sqlite3_column_text(s, 0));
		out[n].duration_s = sqlite3_column_double(s, 1);
		out[n].anomaly_count = sqlite3_column_int(s, 2);
		out[n].n_metrics = 0;
		n++;
	}
	sqlite3_finalize(s);
	return n;
}

// 基线查询: 从 findings.key_metrics_json 中按 metric_key 提取历史值
// target=NULL 聚合整个 module; 否则仅该 target
// 用 Welford 在线算法累加 mean/M2, 避免一次性收集所有值
int storage_get_metric_baseline(const char *module, const char *target,
                                const char *metric_key, double within_sec,
                                baseline_t *out)
{
	if (!storage_is_enabled()) return -1;
	out->mean = 0; out->stddev = 0; out->count = 0;

	const char *sql =
		"SELECT CAST(m.value AS REAL)"
		" FROM findings f, json_each(f.key_metrics_json) m"
		" WHERE f.module = ?"
		"   AND m.key = ?"
		"   AND f.timestamp >= datetime('now', ?)"
		"   AND (? IS NULL OR f.target = ?)"
		" ORDER BY f.timestamp DESC";

	sqlite3_stmt *s;
	if (sqlite3_prepare_v2(g_db, sql, -1, &s, NULL) != SQLITE_OK) {
		fprintf(stderr, "[!] 基线查询预编译失败: %s\n", sqlite3_errmsg(g_db));
		return -1;
	}
	char within_buf[32];
	snprintf(within_buf, sizeof(within_buf), "-%d seconds", (int)within_sec);
	sqlite3_bind_text(s, 1, module, -1, SQLITE_STATIC);
	sqlite3_bind_text(s, 2, metric_key, -1, SQLITE_STATIC);
	sqlite3_bind_text(s, 3, within_buf, -1, SQLITE_STATIC);
	if (target) {
		sqlite3_bind_text(s, 4, target, -1, SQLITE_STATIC);
		sqlite3_bind_text(s, 5, target, -1, SQLITE_STATIC);
	} else {
		sqlite3_bind_null(s, 4);
		sqlite3_bind_null(s, 5);
	}

	// Welford: mean_n = mean_{n-1} + (x - mean_{n-1}) / n
	//          M2_n = M2_{n-1} + (x - mean_{n-1}) * (x - mean_n)
	double mean = 0, M2 = 0;
	int n = 0;
	while (sqlite3_step(s) == SQLITE_ROW) {
		// CAST 失败时 sqlite3_column_double 返回 0.0, 难以与真实 0 区分
		// 但 key_metrics 的数值字段几乎不会是非法字符串, 接受这个噪声
		double x = sqlite3_column_double(s, 0);
		n++;
		double delta = x - mean;
		mean += delta / n;
		M2 += delta * (x - mean);
	}
	sqlite3_finalize(s);

	out->count = n;
	out->mean = mean;
	out->stddev = (n > 1) ? sqrt(M2 / (n - 1)) : 0.0;
	return n;
}

// 双阈值 OR 判定: 固定阈值 OR 基线突增
// 各模块共用, 避免重复实现判定逻辑
int storage_check_baseline_anomaly(const char *module, const char *target,
                                   const char *metric_key, double value,
                                   double fixed_threshold,
                                   baseline_verdict_t *v)
{
	memset(v, 0, sizeof(*v));

	int fixed_hit = (value > fixed_threshold);
	int baseline_hit = 0;

	if (g_cfg.baseline_enabled && storage_is_enabled() && target) {
		baseline_t bl;
		if (storage_get_metric_baseline(module, target, metric_key,
		                                g_cfg.baseline_window_sec, &bl) >= 0 &&
		    bl.count >= g_cfg.baseline_min_samples && bl.stddev > 0) {
			v->baseline_threshold = bl.mean + g_cfg.baseline_z_score * bl.stddev;
			if (value > v->baseline_threshold)
				baseline_hit = 1;
		}
	}

	v->is_anomaly = fixed_hit || baseline_hit;
	v->baseline_triggered = baseline_hit && !fixed_hit;
	return v->is_anomaly;
}

int storage_exec_sql(const char *sql)
{
	if (!g_db) {
		fprintf(stderr, "数据库未打开\n");
		return -1;
	}

	sqlite3_stmt *s;
	if (sqlite3_prepare_v2(g_db, sql, -1, &s, NULL) != SQLITE_OK) {
		fprintf(stderr, "SQL 错误: %s\n", sqlite3_errmsg(g_db));
		return -1;
	}

	int ncol = sqlite3_column_count(s);
	int nrow = 0;

	for (int i = 0; i < ncol; i++)
		printf("%-20s", sqlite3_column_name(s, i));
	printf("\n");
	for (int i = 0; i < ncol * 20; i++)
		putchar('-');
	printf("\n");

	int rc;
	while ((rc = sqlite3_step(s)) == SQLITE_ROW) {
		for (int i = 0; i < ncol; i++) {
			const char *v = (const char *)sqlite3_column_text(s, i);
			printf("%-20s", v ? v : "NULL");
		}
		printf("\n");
		nrow++;
	}

	sqlite3_finalize(s);

	if (rc != SQLITE_DONE)
		fprintf(stderr, "查询中断: %s\n", sqlite3_errmsg(g_db));
	else
		printf("---\n%d 行\n", nrow);

	return nrow;
}

int storage_clear(const char *module)
{
	if (!g_db) {
		fprintf(stderr, "数据库未打开\n");
		return -1;
	}

	if (module) {
		char sql[256];
		snprintf(sql, sizeof(sql),
			"DELETE FROM findings WHERE module='%s';"
			"DELETE FROM snapshots WHERE module='%s';"
			"DELETE FROM reports WHERE module='%s';",
			module, module, module);
		char *err = NULL;
		int rc = sqlite3_exec(g_db, sql, NULL, NULL, &err);
		if (rc != SQLITE_OK) {
			fprintf(stderr, "清除失败: %s\n", err);
			sqlite3_free(err);
			return -1;
		}
		printf("已清除 %s 模块数据\n", module);
	} else {
		char *err = NULL;
		int rc = sqlite3_exec(g_db,
			"DELETE FROM findings;"
			"DELETE FROM snapshots;"
			"DELETE FROM reports;",
			NULL, NULL, &err);
		if (rc != SQLITE_OK) {
			fprintf(stderr, "清除失败: %s\n", err);
			sqlite3_free(err);
			return -1;
		}
		printf("已清除全部数据\n");
	}
	return 0;
}

