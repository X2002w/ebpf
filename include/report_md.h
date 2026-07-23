#ifndef REPORT_MD_H
#define REPORT_MD_H

// report_md.h — JSON→Markdown 渲染器
// 读取统一 JSON 报告，渲染为结构化 Markdown 诊断报告。

int json_to_markdown(const char *json_path, const char *md_path);

#endif
