#ifndef STORAGE_H
#define STORAGE_H

// SQLite 历史数据存储 — 三张表:
//   reports   — 完整 JSON 原文，原始数据回溯
//   findings  — 诊断结论（8 字段拆开存），关联查询与异常统计
//   snapshots — 每模块每窗口关键指标快照，趋势图与重分析
// 数据库: report/eebpf.db, WAL 模式, storage_enabled=1 才启用

// 诊断 finding（对应 JSON findings[] 元素的 8 字段）
#define STORAGE_MAX_STR     256
#define STORAGE_MAX_METRICS 16
#define STORAGE_MAX_EVIDENCE 8

typedef struct {
	char target[STORAGE_MAX_STR];
	int  is_anomaly;
	char subtype[STORAGE_MAX_STR];
	char root_cause[STORAGE_MAX_STR * 4];
	char suggestion[STORAGE_MAX_STR * 4];
	char time_window[STORAGE_MAX_STR];
	char timestamp[64];
	struct {
    char key[STORAGE_MAX_STR];
    char val[STORAGE_MAX_STR]; 
  } metrics[STORAGE_MAX_METRICS];
	int  n_metrics;
	char evidence[STORAGE_MAX_EVIDENCE][STORAGE_MAX_STR * 2];
	int  n_evidence;
} finding_t;

typedef struct {
	char timestamp[64];
	double duration_s;
	int anomaly_count;
	struct { 
    char key[STORAGE_MAX_STR]; 
    char val[STORAGE_MAX_STR]; 
  } metrics[STORAGE_MAX_METRICS];
	int  n_metrics;
} timeline_entry_t;


int storage_init(const char *db_path);
void storage_close(void);
int storage_is_enabled(void);
int storage_save_from_json(const char *module, const char *json_path);
int storage_parse_findings_json(const char *json_path, finding_t *out, int max);
int storage_get_recent_findings(const char *module, double within_sec, finding_t *out, int max);
int storage_get_timeline(const char *module, int limit, timeline_entry_t *out, int max);
int storage_exec_sql(const char *sql);
int storage_clear(const char *module);

#endif
