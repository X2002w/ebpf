// storage.c — SQLite 历史数据存储

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include "sqlite3.h"
#include "../include/storage.h"
#include "../include/config.h"

static sqlite3 *g_db = NULL;

// 从 JSON 行提取 "key": "value" 或 "key": value
static const char *json_val(const char *line, const char *key)
{
	static char buf[4096];
	char pattern[128];
	snprintf(pattern, sizeof(pattern), "\"%s\":", key);
	const char *p = strstr(line, pattern);
	if (!p) 
    return NULL;

	p += strlen(pattern);
	while (*p == ' ') 
    p++;

	if (*p == '"') {
		p++;
		size_t i = 0;
		while (*p && *p != '"' && i < sizeof(buf) - 1)
			buf[i++] = *p++;
		buf[i] = '\0';
		return buf;
	}
	// 数字 / 布尔
	size_t i = 0;
	while (*p && *p != ',' && *p != '\n' && *p != '}' && *p != ']'
	       && i < sizeof(buf) - 1) {
		if (*p != ' ') buf[i++] = *p;
		p++;
	}
	buf[i] = '\0';
	return buf;
}

// 解析 key_metrics: { "k":"v",... } -> finding_t.metrics[]
static void parse_json_kv_obj(FILE *f, finding_t *out)
{
	char buf[4096];
	int in_obj = 1;
	while (in_obj && fgets(buf, sizeof(buf), f)) {
		const char *sep = strstr(buf, "\": \"");
		if (!sep) {
			if (strstr(buf, "}")) 
        in_obj = 0;
			continue;
		}
		const char *ks = buf;
		while (*ks == ' ' || *ks == '\t')
      ks++;
		if (*ks == '"')
      ks++;
		size_t kl = sep - ks;
		if (kl >= STORAGE_MAX_STR)
      kl = STORAGE_MAX_STR - 1;

		int idx = out->n_metrics;
		if (idx >= STORAGE_MAX_METRICS)
      continue;
		memcpy(out->metrics[idx].key, ks, kl);
		out->metrics[idx].key[kl] = '\0';

		const char *vs = sep + 4;
		char *vd = out->metrics[idx].val;
		size_t vi = 0;
		while (*vs && *vs != '"' && vi < STORAGE_MAX_STR - 1)
			vd[vi++] = *vs++;
		vd[vi] = '\0';
		out->n_metrics++;
	}
}

// 解析 evidence: [ "s1", "s2",... ] -> finding_t.evidence[]
static void parse_evidence_arr(FILE *f, finding_t *out)
{
	char buf[4096];
	while (fgets(buf, sizeof(buf), f)) {
		const char *s = buf;
		while (*s == ' ' || *s == '\t') s++;
		if (strncmp(s, "\"evidence\"", 10) == 0) continue;
		if (*s == ']') break;
		const char *q1 = strchr(s, '"');
		if (!q1) continue;
		const char *q2 = strchr(q1 + 1, '"');
		if (!q2) continue;
		size_t len = q2 - q1 - 1;
		if (len >= STORAGE_MAX_STR * 2) len = STORAGE_MAX_STR * 2 - 1;
		if (len > 0 && out->n_evidence < STORAGE_MAX_EVIDENCE) {
			memcpy(out->evidence[out->n_evidence], q1 + 1, len);
			out->evidence[out->n_evidence][len] = '\0';
			out->n_evidence++;
		}

	}
}
// 解析 key_metrics_json: {"key":"val",...} -> finding_t.metrics[]
static void parse_metrics_json_str(const char *json, finding_t *out)
{
	const char *p = json;
	while (*p && out->n_metrics < STORAGE_MAX_METRICS) {
		p = strchr(p, '"');
		if (!p) break;
		p++;
		const char *ke = strchr(p, '"');
		if (!ke) break;
		size_t kl = ke - p;
		if (kl >= STORAGE_MAX_STR) kl = STORAGE_MAX_STR - 1;
		memcpy(out->metrics[out->n_metrics].key, p, kl);
		out->metrics[out->n_metrics].key[kl] = '\0';

		p = strchr(ke + 1, '"');
		if (!p) break;
		p++;
		const char *ve = strchr(p, '"');
		if (!ve) break;
		size_t vl = ve - p;
		if (vl >= STORAGE_MAX_STR) vl = STORAGE_MAX_STR - 1;
		memcpy(out->metrics[out->n_metrics].val, p, vl);
		out->metrics[out->n_metrics].val[vl] = '\0';
		out->n_metrics++;
		p = ve + 1;
	}
}

// 解析 evidence_json: ["s1","s2",...] -> finding_t.evidence[]
static void parse_evidence_json_str(const char *json, finding_t *out)
{
	const char *p = json;
	while (*p && out->n_evidence < STORAGE_MAX_EVIDENCE) {
		p = strchr(p, '"');
		if (!p) break;
		p++;
		const char *e = strchr(p, '"');
		if (!e) break;
		size_t len = e - p;
		if (len > 0) {
			if (len >= STORAGE_MAX_STR * 2) len = STORAGE_MAX_STR * 2 - 1;
			memcpy(out->evidence[out->n_evidence], p, len);
			out->evidence[out->n_evidence][len] = '\0';
			out->n_evidence++;
		}
		p = e + 1;
	}
}


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

// 解析 findings 数组 -> finding_t[]，返回条数
static int parse_findings_from_file(FILE *f, finding_t *out, int max)
{
	char buf[4096];
	int count = 0, in_finding = 0, depth = 0;

	while (fgets(buf, sizeof(buf), f) && count < max) {
		for (char *c = buf; *c; c++) {
			if (*c == '{') depth++;
			else if (*c == '}') depth--;
		}

		if (!in_finding && strstr(buf, "{")) {
			memset(&out[count], 0, sizeof(finding_t));
			in_finding = 1;
		}
		if (!in_finding) continue;

		if (strstr(buf, "\"target\":")) {
			const char *v = json_val(buf, "target");
			if (v) snprintf(out[count].target, STORAGE_MAX_STR, "%s", v);
		} else if (strstr(buf, "\"is_anomaly\":")) {
			const char *v = json_val(buf, "is_anomaly");
			out[count].is_anomaly = (v && strcmp(v, "true") == 0);
		} else if (strstr(buf, "\"subtype\":")) {
			const char *v = json_val(buf, "subtype");
			if (v) snprintf(out[count].subtype, STORAGE_MAX_STR, "%s", v);
		} else if (strstr(buf, "\"root_cause\":")) {
			const char *v = json_val(buf, "root_cause");
			if (v) snprintf(out[count].root_cause, STORAGE_MAX_STR * 4, "%s", v);
		} else if (strstr(buf, "\"suggestion\":")) {
			const char *v = json_val(buf, "suggestion");
			if (v) snprintf(out[count].suggestion, STORAGE_MAX_STR * 4, "%s", v);
		} else if (strstr(buf, "\"time_window\":")) {
			const char *v = json_val(buf, "time_window");
			if (v) snprintf(out[count].time_window, STORAGE_MAX_STR, "%s", v);
		} else if (strstr(buf, "\"key_metrics\":")) {
			parse_json_kv_obj(f, &out[count]);
		} else if (strstr(buf, "\"evidence\":")) {
			parse_evidence_arr(f, &out[count]);
		}

		if (in_finding && depth == 0) {
			in_finding = 0;
			count++;
		}
	}
	return count;
}

// 提取顶层 system 段 KV -> JSON 字符串
static void extract_system_json(FILE *f, char *out, size_t len)
{
	char buf[4096];
	int in_system = 0, depth = 0;
	out[0] = '\0';
	rewind(f);
	while (fgets(buf, sizeof(buf), f)) {
		if (!in_system && strstr(buf, "\"system\":")) {
			in_system = 1;
			if (!strstr(buf, "{")) {
				while (fgets(buf, sizeof(buf), f))
					if (strstr(buf, "{")) break;
			}
			depth = 1;
			continue;
		}
		if (!in_system) continue;
		for (char *c = buf; *c; c++) {
			if (*c == '{') depth++;
			else if (*c == '}') depth--;
		}
		const char *sep = strstr(buf, "\": \"");
		if (sep) {
			const char *kb = buf;
			while (*kb == ' ' || *kb == '\t') kb++;
			if (*kb == '"') kb++;
			char key[STORAGE_MAX_STR] = {};
			size_t kl = sep - kb;
			if (kl >= STORAGE_MAX_STR) kl = STORAGE_MAX_STR - 1;
			memcpy(key, kb, kl);

			const char *vb = sep + 4;
			char val[STORAGE_MAX_STR] = {};
			for (size_t vi = 0; *vb && *vb != '"' && vi < STORAGE_MAX_STR - 1; vi++)
				val[vi] = *vb++;

			int off = strlen(out);
			off += snprintf(out + off, len - off,
					out[0] ? ",\"%s\":\"%s\"" : "\"%s\":\"%s\"",
					key, val);
		}
		if (depth == 0) break;
	}
	// 包裹成 JSON 对象
	char tmp[4096];
	snprintf(tmp, sizeof(tmp), "{%s}", out);
	snprintf(out, len, "%s", tmp);
}

// 解析顶层 meta
static void parse_meta(FILE *f, char *mod, size_t mlen,
		       char *ts, size_t tlen, double *dur)
{
	char buf[4096];
	*mod = *ts = '\0';
	*dur = 0;
	rewind(f);
	while (fgets(buf, sizeof(buf), f)) {
		if (!*mod) {
			const char *v = json_val(buf, "module");
			if (v) snprintf(mod, mlen, "%s", v);
		}
		if (!*ts) {
			const char *v = json_val(buf, "timestamp");
			if (v) snprintf(ts, tlen, "%s", v);
		}
		if (*dur == 0) {
			const char *v = json_val(buf, "duration_s");
			if (v) *dur = atof(v);
		}
		if (*mod && *ts && *dur > 0) break;
	}
	rewind(f);
	while (fgets(buf, sizeof(buf), f))
		if (strstr(buf, "\"type\": \"diagnosis\"")) break;
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

int storage_save_from_json(const char *module, const char *json_path)
{
	if (!storage_is_enabled()) return 0;

	FILE *f = fopen(json_path, "r");
	if (!f) {
    fprintf(stderr, "[!] 无法读取 %s\n", json_path);
    return -1;
  }

	fseek(f, 0, SEEK_END);
	long sz = ftell(f); rewind(f);
	char *raw = malloc(sz + 1);
	if (!raw) { fclose(f); return -1; }
	fread(raw, 1, sz, f); raw[sz] = '\0';

	char ts[64] = {}, mod[32] = {};
	double dur = 0;
	parse_meta(f, mod, sizeof(mod), ts, sizeof(ts), &dur);

	finding_t findings[16];
	int n = parse_findings_from_file(f, findings, 16);

	char sys_json[4096] = {};
	extract_system_json(f, sys_json, sizeof(sys_json));
	fclose(f);

	int rc;
	char *err2 = NULL;
	rc = sqlite3_exec(g_db, "BEGIN TRANSACTION", NULL, NULL, &err2);
	if (rc != SQLITE_OK) {
		fprintf(stderr, "[!] BEGIN TRANSACTION 失败: %s\n", err2);
		sqlite3_free(err2);
		free(raw);
		return -1;
	}

	sqlite3_stmt *s;
	rc = sqlite3_prepare_v2(g_db,
		"INSERT INTO reports (module, timestamp, duration_s, raw_json)"
		" VALUES (?, ?, ?, ?)", -1, &s, NULL);
	if (rc != SQLITE_OK) {
		fprintf(stderr, "[!] 预编译 reports INSERT 失败: %s\n", sqlite3_errmsg(g_db));
		sqlite3_exec(g_db, "ROLLBACK", NULL, NULL, NULL);
		free(raw);
		return -1;
	}
	sqlite3_bind_text(s, 1, mod, -1, SQLITE_STATIC);
	sqlite3_bind_text(s, 2, ts, -1, SQLITE_STATIC);
	sqlite3_bind_double(s, 3, dur);
	sqlite3_bind_text(s, 4, raw, -1, SQLITE_STATIC);
	rc = sqlite3_step(s);
	sqlite3_finalize(s);
	free(raw);
	if (rc != SQLITE_DONE) {
		fprintf(stderr, "[!] INSERT reports 失败: %s\n", sqlite3_errmsg(g_db));
		sqlite3_exec(g_db, "ROLLBACK", NULL, NULL, NULL);
		return -1;
	}

	long long rid = sqlite3_last_insert_rowid(g_db);

	rc = sqlite3_prepare_v2(g_db,
		"INSERT INTO findings (report_id, module, target, is_anomaly,"
		" subtype, root_cause, suggestion, time_window,"
		" key_metrics_json, evidence_json, timestamp)"
		" VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", -1, &s, NULL);
	if (rc != SQLITE_OK) {
		fprintf(stderr, "[!] 预编译 findings INSERT 失败: %s\n", sqlite3_errmsg(g_db));
		sqlite3_exec(g_db, "ROLLBACK", NULL, NULL, NULL);
		return -1;
	}

	for (int i = 0; i < n; i++) {
		finding_t *fd = &findings[i];
		char km[2048] = "{}";
		if (fd->n_metrics > 0) {
			int off = 1;
			for (int j = 0; j < fd->n_metrics; j++)
				off += snprintf(km + off, sizeof(km) - off,
					j ? ",\"%s\":\"%s\"" : "\"%s\":\"%s\"",
					fd->metrics[j].key, fd->metrics[j].val);
			km[off++] = '}'; km[off] = '\0';
		}
		char ev[2048] = "[]";
		if (fd->n_evidence > 0) {
			int off = 1;
			for (int j = 0; j < fd->n_evidence; j++)
				off += snprintf(ev + off, sizeof(ev) - off,
					j ? ",\"%s\"" : "\"%s\"", fd->evidence[j]);
			ev[off++] = ']'; ev[off] = '\0';
		}

		sqlite3_reset(s);
		sqlite3_bind_int64(s, 1, rid);
		sqlite3_bind_text(s, 2, mod, -1, SQLITE_STATIC);
		sqlite3_bind_text(s, 3, fd->target, -1, SQLITE_STATIC);
		sqlite3_bind_int(s, 4, fd->is_anomaly);
		sqlite3_bind_text(s, 5, fd->subtype, -1, SQLITE_STATIC);
		sqlite3_bind_text(s, 6, fd->root_cause, -1, SQLITE_STATIC);
		sqlite3_bind_text(s, 7, fd->suggestion, -1, SQLITE_STATIC);
		sqlite3_bind_text(s, 8, fd->time_window, -1, SQLITE_STATIC);
		sqlite3_bind_text(s, 9, km, -1, SQLITE_STATIC);
		sqlite3_bind_text(s, 10, ev, -1, SQLITE_STATIC);
		sqlite3_bind_text(s, 11, ts, -1, SQLITE_STATIC);
		rc = sqlite3_step(s);
		if (rc != SQLITE_DONE) {
			fprintf(stderr, "[!] INSERT findings[%d] 失败: %s\n", i, sqlite3_errmsg(g_db));
			sqlite3_finalize(s);
			sqlite3_exec(g_db, "ROLLBACK", NULL, NULL, NULL);
			return -1;
		}
	}
	sqlite3_finalize(s);

	rc = sqlite3_prepare_v2(g_db,
		"INSERT INTO snapshots (report_id, module, timestamp, system_json)"
		" VALUES (?, ?, ?, ?)", -1, &s, NULL);
	if (rc != SQLITE_OK) {
		fprintf(stderr, "[!] 预编译 snapshots INSERT 失败: %s\n", sqlite3_errmsg(g_db));
		sqlite3_exec(g_db, "ROLLBACK", NULL, NULL, NULL);
		return -1;
	}
	sqlite3_bind_int64(s, 1, rid);
	sqlite3_bind_text(s, 2, mod, -1, SQLITE_STATIC);
	sqlite3_bind_text(s, 3, ts, -1, SQLITE_STATIC);
	sqlite3_bind_text(s, 4, sys_json, -1, SQLITE_STATIC);
	rc = sqlite3_step(s);
	sqlite3_finalize(s);
	if (rc != SQLITE_DONE) {
		fprintf(stderr, "[!] INSERT snapshots 失败: %s\n", sqlite3_errmsg(g_db));
		sqlite3_exec(g_db, "ROLLBACK", NULL, NULL, NULL);
		return -1;
	}

	rc = sqlite3_exec(g_db, "COMMIT", NULL, NULL, &err2);
	if (rc != SQLITE_OK) {
		fprintf(stderr, "[!] COMMIT 失败: %s\n", err2);
		sqlite3_free(err2);
		sqlite3_exec(g_db, "ROLLBACK", NULL, NULL, NULL);
		return -1;
	}
	return 0;
}

int storage_parse_findings_json(const char *json_path, finding_t *out, int max)
{
	FILE *f = fopen(json_path, "r");
	if (!f) return 0;
	char buf[4096];
	while (fgets(buf, sizeof(buf), f))
		if (strstr(buf, "\"type\": \"diagnosis\"")) break;
	int n = parse_findings_from_file(f, out, max);
	fclose(f);
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
		snprintf(fd->root_cause, STORAGE_MAX_STR * 4, "%s", sqlite3_column_text(s, 3));
		snprintf(fd->suggestion, STORAGE_MAX_STR * 4, "%s", sqlite3_column_text(s, 4));
		snprintf(fd->time_window, STORAGE_MAX_STR, "%s", sqlite3_column_text(s, 5));
		snprintf(fd->timestamp, sizeof(fd->timestamp), "%s", sqlite3_column_text(s, 8));
		const char *km_json = (const char*)sqlite3_column_text(s, 6);
		const char *ev_json = (const char*)sqlite3_column_text(s, 7);
		if (km_json) parse_metrics_json_str(km_json, fd);
		if (ev_json) parse_evidence_json_str(ev_json, fd);
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

