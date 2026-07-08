#ifndef REPORT_MD_H
#define REPORT_MD_H

#include <stdio.h>

// report_md.h — Markdown 诊断报告模块
struct proc_info;
struct stack_entry;

void print_markdown_report(const char *path,
                           struct proc_info *procs, int count,
                           unsigned long long total_interval_ns,
                           int ncpu, double cpu_threshold,
                           struct stack_entry *stacks, int stack_count,
                           unsigned long long total_stack_samples,
                           int stackmap_fd,
                           const char *sched_name, const char *preempt_model,
                           int schedstats_on);

#endif
