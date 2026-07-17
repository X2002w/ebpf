#ifndef REPORT_JSON_H
#define REPORT_JSON_H

#include <stdio.h>

// report_json.h — 统一 JSON 报告构建器
// 各模块采集数据后调用这些 helper 生成结构化 JSON，
// 再由 report_md 渲染为 Markdown。

// 底层原语
void json_str(FILE *out, const char *s);
void json_indent(FILE *out, int n);

// 键值对 (last=1 表示此键值对是当前对象的最后一个，不加逗号)
void json_kv_str(FILE *out, int n, const char *k, const char *v, int last);
void json_kv_int(FILE *out, int n, const char *k, long long v, int last);
void json_kv_uint(FILE *out, int n, const char *k,
		  unsigned long long v, int last);
void json_kv_double(FILE *out, int n, const char *k, double v,
		    const char *fmt, int last);
void json_kv_bool(FILE *out, int n, const char *k, int v, int last);
void json_kv_raw(FILE *out, int n, const char *k, const char *raw, int last);

// 结构边界
void json_obj_begin(FILE *out, int n, const char *k);
void json_obj_end(FILE *out, int n, int last);
void json_arr_begin(FILE *out, int n, const char *k);
void json_arr_end(FILE *out, int n, int last);

// 不带 key 的结构边界 (用于数组元素)
void json_obj_begin_nokey(FILE *out, int n);
void json_arr_begin_nokey(FILE *out, int n);

// 便捷函数
FILE *json_open(const char *path);
void json_close(FILE *out);

#endif
