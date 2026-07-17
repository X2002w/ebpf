// report_json.c — 统一 JSON 报告构建器实现

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include "../include/report_json.h"

// JSON 字符串转义 (含双引号)
void json_str(FILE *out, const char *s)
{
	fputc('"', out);
	for (; *s; s++) {
		switch (*s) {
		case '"':  fputs("\\\"", out); break;
		case '\\': fputs("\\\\", out); break;
		case '\n': fputs("\\n", out); break;
		case '\r': fputs("\\r", out); break;
		case '\t': fputs("\\t", out); break;
		default:   fputc(*s, out);
		}
	}
	fputc('"', out);
}

void json_indent(FILE *out, int n)
{
	for (int i = 0; i < n; i++) fputs("  ", out);
}

void json_kv_str(FILE *out, int n, const char *k, const char *v, int last)
{
	json_indent(out, n);
	json_str(out, k);
	fputs(": ", out);
	json_str(out, v);
	fprintf(out, "%s\n", last ? "" : ",");
}

void json_kv_int(FILE *out, int n, const char *k, long long v, int last)
{
	json_indent(out, n);
	json_str(out, k);
	fprintf(out, ": %lld%s\n", v, last ? "" : ",");
}

void json_kv_uint(FILE *out, int n, const char *k,
		  unsigned long long v, int last)
{
	json_indent(out, n);
	json_str(out, k);
	fprintf(out, ": %llu%s\n", v, last ? "" : ",");
}

void json_kv_double(FILE *out, int n, const char *k, double v,
		    const char *fmt, int last)
{
	json_indent(out, n);
	json_str(out, k);
	fputs(": ", out);
	fprintf(out, fmt, v);
	fprintf(out, "%s\n", last ? "" : ",");
}

void json_kv_bool(FILE *out, int n, const char *k, int v, int last)
{
	json_indent(out, n);
	json_str(out, k);
	fprintf(out, ": %s%s\n", v ? "true" : "false", last ? "" : ",");
}

void json_kv_raw(FILE *out, int n, const char *k, const char *raw, int last)
{
	json_indent(out, n);
	json_str(out, k);
	fprintf(out, ": %s%s\n", raw, last ? "" : ",");
}

void json_obj_begin(FILE *out, int n, const char *k)
{
	json_indent(out, n);
	if (k) { json_str(out, k); fputs(": ", out); }
	fputs("{\n", out);
}

void json_obj_end(FILE *out, int n, int last)
{
	json_indent(out, n);
	fprintf(out, "}%s\n", last ? "" : ",");
}

void json_arr_begin(FILE *out, int n, const char *k)
{
	json_indent(out, n);
	json_str(out, k);
	fputs(": [\n", out);
}

void json_arr_end(FILE *out, int n, int last)
{
	json_indent(out, n);
	fprintf(out, "]%s\n", last ? "" : ",");
}

void json_obj_begin_nokey(FILE *out, int n)
{
	json_indent(out, n);
	fputs("{\n", out);
}

void json_arr_begin_nokey(FILE *out, int n)
{
	json_indent(out, n);
	fputs("[\n", out);
}

FILE *json_open(const char *path)
{
	FILE *out = fopen(path, "w");
	if (!out) {
		mkdir("report", 0755);
		out = fopen(path, "w");
	}
	if (!out)
		fprintf(stderr, "[!] 无法写入 %s: %s\n", path, strerror(errno));
	return out;
}

void json_close(FILE *out)
{
	if (out) fclose(out);
}
