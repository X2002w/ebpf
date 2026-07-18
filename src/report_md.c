// report_md.c — JSON→Markdown 渲染器
// 读取统一 JSON 报告，按 section type 渲染为 Markdown。

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include "../include/report_md.h"
#include "../include/common.h"

#define MAX_LINE 4096
#define MAX_STACK 16
#define MAX_COLS  32
#define MAX_EV    16
#define MAX_FRAMES 256

// 提取行中最后一个双引号字符串 (不含引号), 对应 "key": "value" 中的 value
static int extract_str(const char *line, char *buf, size_t len)
{
	const char *last_start = NULL;
	const char *last_end = NULL;
	const char *s = line;
	while ((s = strchr(s, '"')) != NULL) {
		last_start = s + 1;
		s++;
		const char *e = strchr(s, '"');
		if (!e) break;
		last_end = e;
		s = e + 1;
	}
	if (!last_start || !last_end) return 0;
	size_t n = (size_t)(last_end - last_start);
	if (n >= len) n = len - 1;
	memcpy(buf, last_start, n);
	buf[n] = '\0';
	return 1;
}

// 提取行中第 n 个双引号字符串 (0-indexed)
static int extract_str_n(const char *line, int idx, char *buf, size_t len)
{
	const char *s = line;
	for (int i = 0; i <= idx; i++) {
		s = strchr(s, '"');
		if (!s) return 0;
		s++;
	}
	const char *e = strchr(s, '"');
	if (!e) return 0;
	size_t n = (size_t)(e - s);
	if (n >= len) n = len - 1;
	memcpy(buf, s, n);
	buf[n] = '\0';
	return 1;
}

// 提取整数值 (冒号后面的数字)
static long long extract_int(const char *line)
{
	const char *s = strchr(line, ':');
	if (!s) return 0;
	s++;
	while (*s == ' ' || *s == '\t') s++;
	return atoll(s);
}

// 提取浮点值
static double extract_double(const char *line)
{
	const char *s = strchr(line, ':');
	if (!s) return 0;
	s++;
	while (*s == ' ' || *s == '\t') s++;
	return atof(s);
}

// 提取布尔值
static int extract_bool(const char *line)
{
	return strstr(line, "true") ? 1 : 0;
}

// 行是否包含给定字符串
static int has(const char *line, const char *s)
{
	return strstr(line, s) != NULL;
}

// 写入 report/ 目录下的文件
static FILE *md_open(const char *path)
{
	FILE *out = fopen(path, "w");
	if (!out) {
		mkdir("report", 0755);
		out = fopen(path, "w");
	}
	if (!out)
		fprintf(stderr, "[!] 无法写入 %s\n", path);
	return out;
}

// 渲染 section type=kv 为 Markdown 键值对表格
static void render_kv(FILE *in, FILE *out, const char *title)
{
	fprintf(out, "## %s\n\n", title);
	fprintf(out, "| 指标 | 数值 |\n");
	fprintf(out, "|------|------|\n");

	char line[MAX_LINE];
	while (fgets(line, sizeof(line), in)) {
		if (has(line, "\"rows\":")) continue;
		if (has(line, "]") && !has(line, "[")) break;

		if (!has(line, "{")) continue;

		char key[256] = {}, val[256] = {};

		// 单行格式: {"key": "k", "value": "v"}
		if (has(line, "\"key\":") && has(line, "\"value\":")) {
			extract_str_n(line, 2, key, sizeof(key));
			extract_str_n(line, 6, val, sizeof(val));
			if (key[0])
				fprintf(out, "| %s | %s |\n", key, val);
			continue;
		}

		// 多行格式
		while (fgets(line, sizeof(line), in)) {
			if (has(line, "\"key\":"))
				extract_str(line, key, sizeof(key));
			else if (has(line, "\"value\":"))
				extract_str(line, val, sizeof(val));
			else if (has(line, "}"))
				break;
		}
		if (key[0])
			fprintf(out, "| %s | %s |\n", key, val);
	}
	fprintf(out, "\n");
}

// 从字符串中提取所有引号内容到 cols 数组，返回提取数量
static int extract_quoted_strings(const char *line, char cols[][128], int max)
{
	int n = 0;
	const char *p = line;
	while (n < max) {
		p = strchr(p, '"');
		if (!p) break;
		p++;
		const char *e = strchr(p, '"');
		if (!e) break;
		size_t len = (size_t)(e - p);
		if (len >= 128) len = 127;
		memcpy(cols[n], p, len);
		cols[n][len] = '\0';
		n++;
		p = e + 1;
	}
	return n;
}

// 渲染 section type=table
static void render_table(FILE *in, FILE *out, const char *title)
{
	fprintf(out, "## %s\n\n", title);

	char line[MAX_LINE];
	char cols[MAX_COLS][128];
	int ncols = 0;

	// 读取 columns — 支持单行 ["a","b"] 和多行格式
	int in_cols = 0;
	while (fgets(line, sizeof(line), in)) {
		if (has(line, "\"columns\":")) {
			in_cols = 1;
			// 单行格式: "columns": ["col1", "col2", ...]
			if (has(line, "[")) {
				const char *bracket = strchr(line, '[');
				ncols = extract_quoted_strings(bracket, cols, MAX_COLS);
				if (has(line, "]")) { in_cols = 0; break; }
			}
			continue;
		}

		if (in_cols) {
			if (has(line, "]")) { in_cols = 0; break; }
			// 多行格式: 每行一个引号字符串作为列名
			if (has(line, "\"") && ncols < MAX_COLS) {
				extract_str(line, cols[ncols], sizeof(cols[0]));
				ncols++;
			}
		}
	}

	// 打印表头
	if (ncols == 0) return;
	fprintf(out, "|");
	for (int i = 0; i < ncols; i++)
		fprintf(out, " %s |", cols[i]);
	fprintf(out, "\n|");
	for (int i = 0; i < ncols; i++)
		fprintf(out, "------|");
	fprintf(out, "\n");

	// 读取 rows
	if (!has(line, "\"rows\"")) {
		// scan forward to rows
		while (fgets(line, sizeof(line), in)) {
			if (has(line, "\"rows\":")) break;
			if (has(line, "}") && !has(line, "{")) return; // end of section
		}
	}

	int in_rows = 1;
	while (in_rows && fgets(line, sizeof(line), in)) {
		if (has(line, "]") && has(line, "rows")) continue;
		if (has(line, "]") && !has(line, "[")) { in_rows = 0; break; }
		if (has(line, "}") && !has(line, "{")) break; // end of section

		// 每行是一个数组 [...]，提取所有引号字符串
		if (has(line, "[")) {
			fprintf(out, "|");
			const char *p = line;
			while (*p) {
				p = strchr(p, '"');
				if (!p) break;
				p++;
				const char *e = strchr(p, '"');
				if (!e) break;
				int n = (int)(e - p);
				fprintf(out, " %.*s |", n, p);
				p = e + 1;
			}
			fprintf(out, "\n");
		}
	}
	fprintf(out, "\n");
}

// 渲染 section type=diagnosis
static void render_diagnosis(FILE *in, FILE *out, const char *title)
{
	fprintf(out, "## %s\n\n", title);

	char line[MAX_LINE];
	int seq = 0;

	while (fgets(line, sizeof(line), in)) {
		if (has(line, "\"findings\":")) continue;
		if (has(line, "]") && !has(line, "[")) break; // end of findings
		if (has(line, "}") && !has(line, "{")) break; // end of section

		if (!has(line, "{")) continue;

		seq++;
		char target[256] = {}, subtype[256] = {};
		char root_cause[1024] = {}, suggestion[1024] = {};
		int is_anomaly = 0;
		char evidence[MAX_EV][512];
		int nev = 0;
		struct { char k[128]; char v[128]; } km[MAX_COLS];
		int nkm = 0;
		int in_km = 0, in_ev = 0;

		while (fgets(line, sizeof(line), in)) {
			if (has(line, "\"key_metrics\":")) { in_km = 1; continue; }
			if (has(line, "\"evidence\":")) { in_ev = 1; continue; }

			if (in_km) {
				if (has(line, "}")) { in_km = 0; continue; }
				if (nkm < MAX_COLS) {
					if (extract_str_n(line, 0, km[nkm].k, sizeof(km[0].k)) &&
					    extract_str_n(line, 2, km[nkm].v, sizeof(km[0].v)))
						nkm++;
				}
				continue;
			}

			if (in_ev) {
				if (has(line, "]")) { in_ev = 0; continue; }
				if (nev < MAX_EV) {
					extract_str(line, evidence[nev], sizeof(evidence[0]));
					nev++;
				}
				continue;
			}

			if (has(line, "}") && !has(line, "{")) break;

			if (has(line, "\"target\":")) extract_str(line, target, sizeof(target));
			if (has(line, "\"is_anomaly\":")) is_anomaly = extract_bool(line);
			if (has(line, "\"subtype\":")) extract_str(line, subtype, sizeof(subtype));
			if (has(line, "\"root_cause\":")) extract_str(line, root_cause, sizeof(root_cause));
			if (has(line, "\"suggestion\":")) extract_str(line, suggestion, sizeof(suggestion));
		}

		// 渲染
		fprintf(out, "## [%d] %s\n\n", seq, target[0] ? target : "(unknown)");
		fprintf(out, "**状态**: %s", is_anomaly ? "异常" : "正常");
		if (subtype[0]) fprintf(out, " — *%s*", subtype);
		fprintf(out, "\n\n");

		if (nkm > 0) {
			fprintf(out, "### 关键指标\n\n");
			fprintf(out, "| 指标 | 数值 |\n");
			fprintf(out, "|------|------|\n");
			for (int i = 0; i < nkm; i++)
				fprintf(out, "| %s | **%s** |\n", km[i].k, km[i].v);
			fprintf(out, "\n");
		}

		if (nev > 0) {
			fprintf(out, "### 诊断证据\n\n");
			for (int i = 0; i < nev; i++)
				fprintf(out, "- %s\n", evidence[i]);
			fprintf(out, "\n");
		}

		if (root_cause[0])
			fprintf(out, "### 疑似根因\n\n> %s\n\n", root_cause);
		if (suggestion[0])
			fprintf(out, "### 建议\n\n> %s\n\n", suggestion);

		fprintf(out, "---\n\n");
	}

	if (seq == 0)
		fprintf(out, "> 采样窗口内无异常，系统运行正常。\n\n");
}

// 渲染 section type=stacks
static void render_stacks(FILE *in, FILE *out, const char *title)
{
	char line[MAX_LINE];
	int total = 0;

	// 读取 total_samples
	while (fgets(line, sizeof(line), in)) {
		if (has(line, "\"total_samples\":")) {
			total = (int)extract_int(line);
			break;
		}
		if (has(line, "\"top_stacks\":")) break;
	}

	fprintf(out, "## %s\n\n", title);
	if (total > 0)
		fprintf(out, "总采样: **%d** 次\n\n", total);

	fprintf(out, "| 排名 | 采样次数 | 占比 | 调用栈 |\n");
	fprintf(out, "|------|----------|------|--------|\n");

	while (fgets(line, sizeof(line), in)) {
		if (has(line, "]") && !has(line, "[")) break; // end of top_stacks
		if (has(line, "}") && !has(line, "{")) break; // end of section

		if (!has(line, "{")) continue;

		int rank = 0, count = 0;
		double pct = 0;
		char frames_str[2048] = {};

		while (fgets(line, sizeof(line), in)) {
			if (has(line, "}") && !has(line, "{")) break;

			if (has(line, "\"rank\":")) rank = (int)extract_int(line);
			if (has(line, "\"count\":")) count = (int)extract_int(line);
			if (has(line, "\"pct\":")) pct = extract_double(line);

			if (has(line, "\"frames\":")) {
				// 读取 frames 数组
				while (fgets(line, sizeof(line), in)) {
					if (has(line, "]")) break;
					char frm[256];
					if (extract_str(line, frm, sizeof(frm))) {
						if (strlen(frames_str) + strlen(frm) + 4 < sizeof(frames_str)) {
							if (frames_str[0]) strcat(frames_str, " → ");
							strcat(frames_str, frm);
						}
					}
				}
			}
		}

		char first_frame[128] = {};
		const char *arrow = strstr(frames_str, " → ");
		if (arrow) {
			size_t n = (size_t)(arrow - frames_str);
			if (n >= sizeof(first_frame)) n = sizeof(first_frame) - 1;
			memcpy(first_frame, frames_str, n);
			first_frame[n] = '\0';
		} else {
			strncpy(first_frame, frames_str, sizeof(first_frame) - 1);
		}

		fprintf(out, "| %d | %d | %.1f%% | %s |\n",
			rank, count, pct, first_frame[0] ? first_frame : "(empty)");

		if (frames_str[0]) {
			fprintf(out, "\n<details>\n<summary>Stack #%d 详情</summary>\n\n```\n",
				rank);
			const char *p = frames_str;
			int depth = 0;
			char part[256];
			while (*p) {
				const char *arrow2 = strstr(p, " → ");
				size_t n = arrow2 ? (size_t)(arrow2 - p) : strlen(p);
				if (n >= sizeof(part)) n = sizeof(part) - 1;
				memcpy(part, p, n);
				part[n] = '\0';
				fprintf(out, "  #%-2d  %s\n", depth++, part);
				if (!arrow2) break;
				p = arrow2 + strlen(" → ");
				while (*p == ' ') p++;
			}
			fprintf(out, "```\n</details>\n\n");
		}
	}

	fprintf(out, "\n");
}

// 主入口: 读取 JSON 文件，按 section 渲染 Markdown
int json_to_markdown(const char *json_path, const char *md_path)
{
	FILE *in = fopen(json_path, "r");
	if (!in) {
		fprintf(stderr, "[!] 无法读取 JSON: %s\n", json_path);
		return -1;
	}

	FILE *out = md_open(md_path);
	if (!out) {
		fclose(in);
		return -1;
	}

	char line[MAX_LINE];
	char module[32] = "unknown";
	char timestamp[64] = {};
	double duration_s = 0;

	// 读取顶层元数据
	while (fgets(line, sizeof(line), in)) {
		if (has(line, "\"module\":")) extract_str(line, module, sizeof(module));
		if (has(line, "\"timestamp\":")) extract_str(line, timestamp, sizeof(timestamp));
		if (has(line, "\"duration_s\":")) duration_s = extract_double(line);
		if (has(line, "\"system\":")) break;
		if (has(line, "\"sections\":")) break;
	}

	// 标题
	const char *report_title = "系统异常观测诊断报告";
	if (strcmp(module, "cpu") == 0)      report_title = "CPU 异常观测诊断报告";
	else if (strcmp(module, "io") == 0)  report_title = "I/O 异常观测诊断报告";
	else if (strcmp(module, "mem") == 0) report_title = "内存抖动观测诊断报告";
	else if (strcmp(module, "lock") == 0) report_title = "锁竞争异常观测诊断报告";
	else if (strcmp(module, "hot") == 0)  report_title = "系统调用热点观测诊断报告";

	fprintf(out, "# %s\n\n", report_title);
	fprintf(out, "| 项目 | 内容 |\n");
	fprintf(out, "|------|------|\n");
	fprintf(out, "| **异常时间窗口** | %s |\n", timestamp);
	fprintf(out, "| **采样间隔** | %.1fs |\n\n", duration_s);

	// 系统概览
	if (has(line, "\"system\":")) {
		fprintf(out, "## 系统概览\n\n");
		fprintf(out, "| 指标 | 数值 |\n");
		fprintf(out, "|------|------|\n");

		while (fgets(line, sizeof(line), in)) {
			if (has(line, "}")) break; // end of system

			char key[128] = {}, val[128] = {};
			if (extract_str_n(line, 0, key, sizeof(key)) &&
			    extract_str_n(line, 2, val, sizeof(val))) {
				fprintf(out, "| %s | %s |\n", key, val);
			}
		}
		fprintf(out, "\n");
	}

	// 扫描到 sections
	while (fgets(line, sizeof(line), in)) {
		if (has(line, "\"sections\":")) break;
		if (has(line, "}")) goto done; // root object end, no sections
	}

	// 处理 sections
	while (fgets(line, sizeof(line), in)) {
		if (has(line, "]") && !has(line, "[")) break;

		if (!has(line, "\"type\":")) continue;

		char type[32] = {};
		char title[256] = {};
		extract_str(line, type, sizeof(type));

		// 读取 title
		while (fgets(line, sizeof(line), in)) {
			if (has(line, "\"title\":")) {
				extract_str(line, title, sizeof(title));
				break;
			}
			if (has(line, "{")) break; // no title, start of content
		}

		if (strcmp(type, "kv") == 0)
			render_kv(in, out, title);
		else if (strcmp(type, "table") == 0)
			render_table(in, out, title);
		else if (strcmp(type, "diagnosis") == 0)
			render_diagnosis(in, out, title);
		else if (strcmp(type, "stacks") == 0)
			render_stacks(in, out, title);
	}

done:
	fclose(in);
	fclose(out);
	fprintf(stderr, "[*] Markdown 报告已写入 %s\n", md_path);
	return 0;
}
