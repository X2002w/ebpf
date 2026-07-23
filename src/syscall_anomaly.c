#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <getopt.h>
#include <errno.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "syscall_anomaly.skel.h"
#include "../include/syscall_anomaly.h"
#include "../include/syscall_names.h"
#include "../include/utils.h"
#include "../include/report_json.h"
#include "../include/report_md.h"
#include "../include/common.h"
#include "../include/config.h"

struct syscall_stats {
	unsigned long long count;
	unsigned long long total_ns;
	unsigned long long max_ns;
	unsigned long long err_count;
};

struct pid_nr_stats {
	unsigned long long count;
	unsigned long long total_ns;
	unsigned long long max_ns;
};

static const char *syscall_name(unsigned int nr)
{
	if (nr < sizeof(syscall_names) / sizeof(syscall_names[0]) &&
	    syscall_names[nr])
		return syscall_names[nr];

	static char buf[32];
	snprintf(buf, sizeof(buf), "syscall_%u", nr);
	return buf;
}

// 等待型系统调用: 高耗时是正常语义，不作为异常依据
static int is_wait_syscall(unsigned int nr)
{
	switch (nr) {
#ifdef __NR_poll
	case __NR_poll:
#endif
#ifdef __NR_select
	case __NR_select:
#endif
#ifdef __NR_epoll_wait
	case __NR_epoll_wait:
#endif
#ifdef __NR_nanosleep
	case __NR_nanosleep:
#endif
#ifdef __NR_clock_nanosleep
	case __NR_clock_nanosleep:
#endif
#ifdef __NR_pselect6
	case __NR_pselect6:
#endif
#ifdef __NR_ppoll
	case __NR_ppoll:
#endif
#ifdef __NR_epoll_pwait
	case __NR_epoll_pwait:
#endif
#ifdef __NR_epoll_pwait2
	case __NR_epoll_pwait2:
#endif
		return 1;
	default:
		return 0;
	}
}

struct syscall_entry {
	unsigned int nr;
	struct syscall_stats stats;
};

static int cmp_count(const void *a, const void *b)
{
	const struct syscall_entry *sa = a, *sb = b;
	return (sb->stats.count > sa->stats.count) -
	       (sa->stats.count > sb->stats.count);
}

static int cmp_lat(const void *a, const void *b)
{
	const struct syscall_entry *sa = a, *sb = b;
	double la = sa->stats.count ? (double)sa->stats.total_ns / sa->stats.count : 0;
	double lb = sb->stats.count ? (double)sb->stats.total_ns / sb->stats.count : 0;
	return (lb > la) - (la > lb);
}

static int collect_sys_stats(int map_fd, struct syscall_entry **out, int *n)
{
	int cap = 256, cnt = 0;
	*out = malloc(cap * sizeof(struct syscall_entry));
	if (!*out) return -1;

	unsigned int key = 0, next;
	while (bpf_map_get_next_key(map_fd, &key, &next) == 0) {
		struct syscall_stats val = {};
		if (bpf_map_lookup_elem(map_fd, &next, &val) != 0) {
			key = next;
			continue;
		}
		if (cnt >= cap) {
			cap *= 2;
			*out = realloc(*out, cap * sizeof(struct syscall_entry));
			if (!*out) return -1;
		}
		(*out)[cnt].nr = next;
		(*out)[cnt].stats = val;
		cnt++;
		key = next;
	}
	*n = cnt;
	return 0;
}

struct pid_summary {
	unsigned int tid;
	unsigned long long total_count;
	unsigned long long total_ns;
	unsigned long long max_ns;
	unsigned int top_nr;           // 次数最多的系统调用
	unsigned long long top_nr_count;
	unsigned int top_lat_nr;       // 耗时最多的系统调用
	unsigned long long top_lat_ns;
	char comm[16];
};

static int cmp_pid(const void *a, const void *b)
{
	const struct pid_summary *pa = a, *pb = b;
	return (pb->total_count > pa->total_count) -
	       (pa->total_count > pb->total_count);
}

static int collect_pid_summary(int map_fd, struct pid_summary **out, int *n)
{
	int cap = 256, cnt = 0;
	*out = malloc(cap * sizeof(struct pid_summary));
	if (!*out) return -1;

	unsigned long long key = 0, next;
	while (bpf_map_get_next_key(map_fd, &key, &next) == 0) {
		struct pid_nr_stats val = {};
		if (bpf_map_lookup_elem(map_fd, &next, &val) != 0) {
			key = next;
			continue;
		}

		unsigned int tid = (unsigned int)(next >> 32);

		struct pid_summary *found = NULL;
		for (int i = 0; i < cnt; i++) {
			if ((*out)[i].tid == tid) { found = &(*out)[i]; break; }
		}

		if (!found) {
			if (cnt >= cap) {
				cap *= 2;
				*out = realloc(*out, cap * sizeof(struct pid_summary));
				if (!*out) return -1;
			}
			found = &(*out)[cnt];
			memset(found, 0, sizeof(*found));
			found->tid = tid;
			read_comm(tid, found->comm, sizeof(found->comm));
			cnt++;
		}

		found->total_count += val.count;
		found->total_ns += val.total_ns;
		if (val.max_ns > found->max_ns)
			found->max_ns = val.max_ns;
		if (val.count > found->top_nr_count) {
			found->top_nr_count = val.count;
      // 取低 32 位拿到系统调用号
			found->top_nr = (unsigned int)(next & 0xFFFFFFFF);
		}
		if (val.total_ns > found->top_lat_ns) {
			found->top_lat_ns = val.total_ns;
			found->top_lat_nr = (unsigned int)(next & 0xFFFFFFFF);
		}

		key = next;
	}

	qsort(*out, cnt, sizeof(struct pid_summary), cmp_pid);
	*n = cnt;
	return 0;
}

static void print_report(FILE *out,
                         struct syscall_entry *entries, int n,
                         struct pid_summary *pids, int pn,
                         unsigned long long interval_ns)
{
	char ts[32];
	iso_timestamp(ts, sizeof(ts));
	double duration_s = (double)interval_ns / 1e9;

	unsigned long long grand_total = 0, grand_ns = 0, grand_err = 0;
	for (int i = 0; i < n; i++) {
		grand_total += entries[i].stats.count;
		grand_ns += entries[i].stats.total_ns;
		grand_err += entries[i].stats.err_count;
	}

	fprintf(out,
		"=================================================================\n"
		"  系统调用热点观测诊断报告\n"
		"=================================================================\n"
		"  时间窗口: %s  (间隔 %.1fs)\n"
		"  系统调用总数: %llu  |  总耗时: %.1fms  |  错误数: %llu\n"
		"=================================================================\n\n",
		ts, duration_s, grand_total,
		(double)grand_ns / 1e6, grand_err);

	qsort(entries, n, sizeof(struct syscall_entry), cmp_count);
	int top = n < 10 ? n : 10;
	fprintf(out, "  高频系统调用 Top-%d (每秒调用次数)\n", top);
	fprintf(out, "  %-22s %10s %10s %8s %8s\n",
	        "syscall", "count", "/s", "avg(us)", "max(ms)");
	for (int i = 0; i < top; i++) {
		struct syscall_stats *s = &entries[i].stats;
		double rate = (double)s->count / duration_s;
		double avg_us = s->count ? (double)s->total_ns / s->count / 1000.0 : 0;
		double max_ms = (double)s->max_ns / 1e6;
		const char *flag = rate > g_cfg.hot_freq_per_sec ? " <-- 高频" : "";
		fprintf(out, "  %-22s %10llu %10.0f %8.0f %8.1f%s\n",
		        syscall_name(entries[i].nr), s->count, rate, avg_us, max_ms, flag);
	}
	fprintf(out, "\n");

	qsort(entries, n, sizeof(struct syscall_entry), cmp_lat);
	fprintf(out, "  高耗时系统调用 Top-%d (平均等待时间)\n", top);
	fprintf(out, "  %-22s %10s %10s %8s %8s %8s\n",
	        "syscall", "count", "/s", "avg(us)", "max(ms)", "err%");
	for (int i = 0; i < top; i++) {
		struct syscall_stats *s = &entries[i].stats;
		double rate = (double)s->count / duration_s;
		double avg_us = s->count ? (double)s->total_ns / s->count / 1000.0 : 0;
		double max_ms = (double)s->max_ns / 1e6;
		double err_pct = s->count ? (double)s->err_count / s->count * 100.0 : 0;
		const char *flag = avg_us > g_cfg.hot_lat_us ? " <-- 高耗时" : "";
		fprintf(out, "  %-22s %10llu %10.0f %8.0f %8.1f %7.1f%%%s\n",
		        syscall_name(entries[i].nr), s->count, rate,
		        avg_us, max_ms, err_pct, flag);
	}
	fprintf(out, "\n");

	fprintf(out, "  进程系统调用汇总 Top-15 (按调用次数排序)\n");
	fprintf(out, "  %-8s %-16s %10s %10s %8s %8s\n",
	        "TID", "comm", "count", "/s", "avg(us)", "max(ms)");
	int ptop = pn < 15 ? pn : 15;
	for (int i = 0; i < ptop; i++) {
		struct pid_summary *p = &pids[i];
		double rate = (double)p->total_count / duration_s;
		double avg_us = p->total_count ?
			(double)p->total_ns / p->total_count / 1000.0 : 0;
		double max_ms = (double)p->max_ns / 1e6;
		fprintf(out, "  %-8u %-16s %10llu %10.0f %8.0f %8.1f\n",
		        p->tid, p->comm, p->total_count, rate, avg_us, max_ms);
	}
	fprintf(out, "\n");

	int diag_count = 0;
	fprintf(out, "  诊断结论\n");

	qsort(entries, n, sizeof(struct syscall_entry), cmp_count);
	for (int i = 0; i < n; i++) {
		struct syscall_stats *s = &entries[i].stats;
		double rate = (double)s->count / duration_s;
		double avg_us = s->count ? (double)s->total_ns / s->count / 1000.0 : 0;
		double err_pct = s->count ? (double)s->err_count / s->count * 100.0 : 0;

		if (rate <= g_cfg.hot_freq_per_sec && avg_us <= g_cfg.hot_lat_us && err_pct <= g_cfg.hot_err_rate * 100)
			continue;

		diag_count++;
		fprintf(out, "\n  [%d] %s", diag_count, syscall_name(entries[i].nr));

		const char *type = NULL;
		if (rate > g_cfg.hot_freq_per_sec && avg_us > g_cfg.hot_lat_us)
			type = "高频 + 高耗时";
		else if (rate > g_cfg.hot_freq_per_sec)
			type = "高频调用";
		else if (avg_us > g_cfg.hot_lat_us)
			type = is_wait_syscall(entries[i].nr) ? "等待 (正常)" : "高耗时";
		else
			type = "高错误率";
		fprintf(out, "  —  %s\n", type);

	fprintf(out, "      调用次数: %llu (%.0f/s, 阈值 %d/s)  |  ""平均耗时: %.0fus (阈值 %d us)  |  最大耗时: %.1fms\n",
	        s->count, rate, g_cfg.hot_freq_per_sec, avg_us, g_cfg.hot_lat_us, (double)s->max_ns / 1e6);
		if (err_pct > 0)
			fprintf(out, "      错误率: %.1f%% (%llu/%llu)\n", err_pct, s->err_count, s->count);

		if (rate > g_cfg.hot_freq_per_sec && avg_us <= g_cfg.hot_lat_us)
			fprintf(out,
			        "      疑似根因: 事件循环或 busy-poll 导致短耗时系统调用高频重复\n"
			        "      建议: 检查轮询逻辑，改用阻塞+超时或事件驱动模式\n");
		else if (avg_us > g_cfg.hot_lat_us && is_wait_syscall(entries[i].nr))
			fprintf(out,
			        "      疑似根因: 事件等待型系统调用，高耗时说明无事件到达或超时设置较长\n"
			        "      建议: 属正常等待行为；若期望快速响应，检查 fd 活跃度和超时参数\n");
		else if (avg_us > g_cfg.hot_lat_us)
			fprintf(out,
			        "      疑似根因: 系统调用阻塞等待 I/O、锁或网络资源\n"
			        "      建议: 排查底层资源竞争，考虑异步 I/O 或批量操作\n");
		else
			fprintf(out,
			        "      疑似根因: 系统调用参数错误或资源不可用\n"
			        "      建议: 检查调用参数合法性及系统资源状态\n");
	}

	qsort(pids, pn, sizeof(struct pid_summary), cmp_pid);
	int pdiag = 0;
	for (int i = 0; i < pn && pdiag < 10; i++) {
		struct pid_summary *p = &pids[i];
		double rate = (double)p->total_count / duration_s;
		double avg_us = p->total_count ?
			(double)p->total_ns / p->total_count / 1000.0 : 0;

		if (rate <= g_cfg.hot_freq_per_sec && avg_us <= g_cfg.hot_lat_us)
			continue;

		pdiag++;
		fprintf(out, "\n  [进程%d] TID %u (%s)  —  %s\n",
		        pdiag, p->tid, p->comm,
		        avg_us > g_cfg.hot_lat_us ? "高耗时" : "高频调用");
	fprintf(out, "      系统调用总数: %llu (%.0f/s, 阈值 %d/s)  |  ""平均耗时: %.0fus (阈值 %d us)\n",
	        p->total_count, rate, g_cfg.hot_freq_per_sec, avg_us, g_cfg.hot_lat_us);
		fprintf(out, "      最多调用: %s (%llu次)  |  耗时最多: %s (%.1fms)\n",
		        syscall_name(p->top_nr), p->top_nr_count,
		        syscall_name(p->top_lat_nr), (double)p->top_lat_ns / 1e6);

		if (avg_us > g_cfg.hot_lat_us && is_wait_syscall(p->top_lat_nr))
			fprintf(out,
			        "      疑似根因: 线程主要时间在事件等待 (%s)，属正常 I/O 多路复用行为\n"
			        "      建议: 无明显异常；若需降低时延，检查 fd 活跃度或调小超时\n",
			        syscall_name(p->top_lat_nr));
		else if (avg_us > g_cfg.hot_lat_us)
			fprintf(out,
			        "      疑似根因: 线程大量时间消耗在阻塞型系统调用 (%s)\n"
			        "      建议: 分析 %s 调用路径，考虑异步化或减少阻塞时间\n",
			        syscall_name(p->top_lat_nr), syscall_name(p->top_lat_nr));
		else
			fprintf(out,
			        "      疑似根因: 线程频繁调用短耗时系统调用 (%s)，可能存在轮询模式\n"
			        "      建议: 审查 %s 调用频率，调整轮询间隔或切换事件驱动\n",
			        syscall_name(p->top_nr), syscall_name(p->top_nr));
	}

	if (diag_count == 0 && pdiag == 0)
		fprintf(out, "  (当前系统调用指标在正常范围内)\n");

	fflush(out);
}

static void reset_u64_map(int map_fd)
{
	unsigned long long key = 0, next;
	while (bpf_map_get_next_key(map_fd, &key, &next) == 0) {
		bpf_map_delete_elem(map_fd, &next);
		key = next;
	}
}

// 统一 JSON 报告
static void print_syscall_json_report(struct syscall_entry *entries, int n,
				       struct pid_summary *pids, int pn,
				       unsigned long long interval_ns)
{
	const char *path = "report/hot.json";
	FILE *out = json_open(path);
	if (!out) return;

	char ts[32], buf[256];
	iso_timestamp(ts, sizeof(ts));
	double duration_s = (double)interval_ns / 1e9;

	unsigned long long grand_total = 0, grand_ns = 0, grand_err = 0;
	for (int i = 0; i < n; i++) {
		grand_total += entries[i].stats.count;
		grand_ns += entries[i].stats.total_ns;
		grand_err += entries[i].stats.err_count;
	}

	fprintf(out, "{\n");
	json_kv_str(out, 1, "module", "hot", 0);
	json_kv_str(out, 1, "timestamp", ts, 0);
	json_kv_double(out, 1, "duration_s", duration_s, "%.1f", 0);

	json_obj_begin(out, 1, "system");
	snprintf(buf, sizeof(buf), "%llu", grand_total);
	json_kv_str(out, 2, "系统调用总数", buf, 0);
	snprintf(buf, sizeof(buf), "%.1fms", (double)grand_ns / 1e6);
	json_kv_str(out, 2, "总耗时", buf, 0);
	snprintf(buf, sizeof(buf), "%llu", grand_err);
	json_kv_str(out, 2, "错误数", buf, 1);
	json_obj_end(out, 1, 0);

	json_arr_begin(out, 1, "sections");

	// section: top by frequency
	qsort(entries, n, sizeof(struct syscall_entry), cmp_count);
	{
		json_obj_begin_nokey(out, 2);
		json_kv_str(out, 3, "type", "table", 0);
		json_kv_str(out, 3, "title", "高频系统调用 Top-10", 0);
		fprintf(out, "          \"columns\": [\"系统调用\", \"调用次数\", \"每秒\", \"avg(us)\", \"max(ms)\", \"错误率\", \"标记\"],\n");
		json_arr_begin(out, 3, "rows");
		int top = n < 10 ? n : 10;
		for (int i = 0; i < top; i++) {
			struct syscall_stats *s = &entries[i].stats;
			double rate = (double)s->count / duration_s;
			double avg_us = s->count ? (double)s->total_ns / s->count / 1000.0 : 0;
			double max_ms = (double)s->max_ns / 1e6;
			double err_pct = s->count ? (double)s->err_count / s->count * 100.0 : 0;
			const char *flag = rate > 10000 ? "高频" : avg_us > 10000 ? "高耗时" : err_pct > 10 ? "高错误率" : "";
			json_indent(out, 4);
			fprintf(out, "[\"%s\", \"%llu\", \"%.0f\", \"%.0f\", \"%.1f\", \"%.1f%%\", \"%s\"]%s\n",
				syscall_name(entries[i].nr), s->count, rate, avg_us, max_ms, err_pct, flag,
				i < top - 1 ? "," : "");
		}
		json_arr_end(out, 3, 1);
		json_obj_end(out, 2, 0);
	}

	// section: top by latency
	qsort(entries, n, sizeof(struct syscall_entry), cmp_lat);
	{
		json_obj_begin_nokey(out, 2);
		json_kv_str(out, 3, "type", "table", 0);
		json_kv_str(out, 3, "title", "高耗时系统调用 Top-10", 0);
		fprintf(out, "          \"columns\": [\"系统调用\", \"调用次数\", \"每秒\", \"avg(us)\", \"max(ms)\", \"错误率\", \"标记\"],\n");
		json_arr_begin(out, 3, "rows");
		int top = n < 10 ? n : 10;
		for (int i = 0; i < top; i++) {
			struct syscall_stats *s = &entries[i].stats;
			double rate = (double)s->count / duration_s;
			double avg_us = s->count ? (double)s->total_ns / s->count / 1000.0 : 0;
			double max_ms = (double)s->max_ns / 1e6;
			double err_pct = s->count ? (double)s->err_count / s->count * 100.0 : 0;
			const char *flag = avg_us > 10000 ? "高耗时" : "";
			json_indent(out, 4);
			fprintf(out, "[\"%s\", \"%llu\", \"%.0f\", \"%.0f\", \"%.1f\", \"%.1f%%\", \"%s\"]%s\n",
				syscall_name(entries[i].nr), s->count, rate, avg_us, max_ms, err_pct, flag,
				i < top - 1 ? "," : "");
		}
		json_arr_end(out, 3, 1);
		json_obj_end(out, 2, 0);
	}

	// section: process summary table (sorted by count desc)
	qsort(pids, pn, sizeof(struct pid_summary), cmp_pid);
	{
		json_obj_begin_nokey(out, 2);
		json_kv_str(out, 3, "type", "table", 0);
		json_kv_str(out, 3, "title", "进程系统调用汇总", 0);
		fprintf(out, "          \"columns\": [\"TID\", \"进程\", \"调用次数\", \"/s\", \"avg(us)\", \"max(ms)\"],\n");
		json_arr_begin(out, 3, "rows");

		int ptop = pn < 15 ? pn : 15;
		for (int i = 0; i < ptop; i++) {
			struct pid_summary *p = &pids[i];
			double rate = (double)p->total_count / duration_s;
			double avg_us = p->total_count ?
				(double)p->total_ns / p->total_count / 1000.0 : 0;
			double max_ms = (double)p->max_ns / 1e6;

			json_indent(out, 4);
			fprintf(out, "[\"%u\", \"%s\", \"%llu\", \"%.0f\", \"%.0f\", \"%.1f\"]%s\n",
				p->tid, p->comm, p->total_count, rate, avg_us, max_ms,
				i < ptop - 1 ? "," : "");
		}
		fprintf(out, "\n");
		json_arr_end(out, 3, 1);
		json_obj_end(out, 2, 0);
	}

	// section: diagnosis
	{
		json_obj_begin_nokey(out, 2);
		json_kv_str(out, 3, "type", "diagnosis", 0);
		json_kv_str(out, 3, "title", "诊断结论", 0);
		json_arr_begin(out, 3, "findings");

		// 按调用次数排序，诊断 syscall 级别异常
		qsort(entries, n, sizeof(struct syscall_entry), cmp_count);
		int diag = 0;

		for (int i = 0; i < n; i++) {
			struct syscall_stats *s = &entries[i].stats;
			double rate = (double)s->count / duration_s;
			double avg_us = s->count ? (double)s->total_ns / s->count / 1000.0 : 0;
			double err_pct = s->count ? (double)s->err_count / s->count * 100.0 : 0;

			if (rate <= g_cfg.hot_freq_per_sec && avg_us <= g_cfg.hot_lat_us && err_pct <= g_cfg.hot_err_rate * 100)
				continue;

			const char *type = NULL;
			const char *root_cause = NULL;
			const char *suggestion = NULL;

			int is_anomaly = 1;

			if (rate > g_cfg.hot_freq_per_sec && avg_us > g_cfg.hot_lat_us) {
				type = "高频 + 高耗时";
				root_cause = "系统调用频繁调用且耗时偏高";
				suggestion = "检查调用频率和阻塞原因，考虑异步化或批量操作";
			} else if (rate > g_cfg.hot_freq_per_sec) {
				type = "高频调用";
				root_cause = "事件循环或 busy-poll 导致短耗时系统调用高频重复";
				suggestion = "检查轮询逻辑，改用阻塞+超时或事件驱动模式";
			} else if (avg_us > g_cfg.hot_lat_us && is_wait_syscall(entries[i].nr)) {
				type = "等待 (正常)";
				root_cause = "事件等待型系统调用，高耗时说明无事件到达或超时设置较长";
				suggestion = "属正常等待行为；若期望快速响应，检查 fd 活跃度和超时参数";
				is_anomaly = 0;
			} else if (avg_us > g_cfg.hot_lat_us) {
				type = "高耗时";
				root_cause = "系统调用阻塞等待 I/O、锁或网络资源";
				suggestion = "排查底层资源竞争，考虑异步 I/O 或批量操作";
			} else {
				type = "高错误率";
				root_cause = "系统调用参数错误或资源不可用";
				suggestion = "检查调用参数合法性及系统资源状态";
			}

			if (diag > 0) fprintf(out, ",\n");
			json_indent(out, 4);
			fprintf(out, "{\n");

			char tbuf[128];
			snprintf(tbuf, sizeof(tbuf), "%s (syscall)", syscall_name(entries[i].nr));
			json_kv_str(out, 5, "target", tbuf, 0);
			json_kv_bool(out, 5, "is_anomaly", is_anomaly, 0);
			json_kv_str(out, 5, "subtype", type, 0);
			json_kv_str(out, 5, "root_cause", root_cause, 0);
			json_kv_str(out, 5, "suggestion", suggestion, 0);

			snprintf(buf, sizeof(buf), "%s +%.0fs", ts, duration_s);
			json_kv_str(out, 5, "time_window", buf, 0);

			json_obj_begin(out, 5, "key_metrics");
			char kmbuf[128];
			snprintf(kmbuf, sizeof(kmbuf), "%llu (%.0f/s)", s->count, rate);
			json_kv_str(out, 6, "调用次数", kmbuf, 0);
			snprintf(kmbuf, sizeof(kmbuf), "%.0f us", avg_us);
			json_kv_str(out, 6, "平均耗时", kmbuf, 0);
			snprintf(kmbuf, sizeof(kmbuf), "%.1f ms", (double)s->max_ns / 1e6);
			json_kv_str(out, 6, "最大耗时", kmbuf, 0);
			snprintf(kmbuf, sizeof(kmbuf), "%.1f%%", err_pct);
			json_kv_str(out, 6, "错误率", kmbuf, 1);
			json_obj_end(out, 5, 0);

			fprintf(out, "            \"evidence\": [\n");
			if (rate > g_cfg.hot_freq_per_sec && avg_us > g_cfg.hot_lat_us)
				fprintf(out, "              \"%s 调用 %llu 次 (%.0f/s, 阈值 %d/s), 平均耗时 %.0f us (阈值 %d us), 双高异常\"\n",
					syscall_name(entries[i].nr), s->count, rate, g_cfg.hot_freq_per_sec, avg_us, g_cfg.hot_lat_us);
			else if (rate > g_cfg.hot_freq_per_sec)
				fprintf(out, "              \"%s 调用 %llu 次 (%.0f/s, 阈值 %d/s), 平均耗时 %.0f us\"\n",
					syscall_name(entries[i].nr), s->count, rate, g_cfg.hot_freq_per_sec, avg_us);
			else if (avg_us > g_cfg.hot_lat_us && is_wait_syscall(entries[i].nr))
				fprintf(out, "              \"%s 调用 %llu 次 (%.0f/s), 平均耗时 %.0f us (阈值 %d us), 事件等待型\"\n",
					syscall_name(entries[i].nr), s->count, rate, avg_us, g_cfg.hot_lat_us);
			else if (avg_us > g_cfg.hot_lat_us)
				fprintf(out, "              \"%s 调用 %llu 次 (%.0f/s), 平均耗时 %.0f us (阈值 %d us)\"\n",
					syscall_name(entries[i].nr), s->count, rate, avg_us, g_cfg.hot_lat_us);
			else
				fprintf(out, "              \"%s 错误率 %.1f%% (阈值 %.0f%%), %llu/%llu 次失败\"\n",
					syscall_name(entries[i].nr), err_pct, g_cfg.hot_err_rate * 100, s->err_count, s->count);
			fprintf(out, "            ]\n");

			diag++;
			json_obj_end(out, 4, 1);
		}

		// 进程级别诊断
		qsort(pids, pn, sizeof(struct pid_summary), cmp_pid);
		int pdiag = 0;
		for (int i = 0; i < pn && pdiag < 10; i++) {
			struct pid_summary *p = &pids[i];
			double rate = (double)p->total_count / duration_s;
			double avg_us = p->total_count ?
				(double)p->total_ns / p->total_count / 1000.0 : 0;

			if (rate <= g_cfg.hot_freq_per_sec && avg_us <= g_cfg.hot_lat_us)
				continue;

			const char *ptype = NULL;
			const char *proot_cause = NULL;
			const char *psuggestion = NULL;
			int pis_anomaly = 1;

			if (avg_us > g_cfg.hot_lat_us && is_wait_syscall(p->top_lat_nr)) {
				ptype = "等待 (正常)";
				proot_cause = "线程主要时间在事件等待，属正常 I/O 多路复用行为";
				psuggestion = "无明显异常；若需降低时延，检查 fd 活跃度或调小超时";
				pis_anomaly = 0;
			} else if (avg_us > g_cfg.hot_lat_us) {
				ptype = "高耗时";
				proot_cause = "线程大量时间消耗在阻塞型系统调用";
				psuggestion = "分析调用路径，考虑异步化或减少阻塞时间";
			} else {
				ptype = "高频调用";
				proot_cause = "线程频繁调用短耗时系统调用，可能存在轮询模式";
				psuggestion = "审查调用频率，调整轮询间隔或切换事件驱动";
			}

			if (diag > 0 || pdiag > 0) {
				if (diag > 0) fprintf(out, ",\n");
				diag++;
			}

			json_indent(out, 4);
			fprintf(out, "{\n");

			char tbuf[128];
			snprintf(tbuf, sizeof(tbuf), "%s (TID %u)", p->comm, p->tid);
			json_kv_str(out, 5, "target", tbuf, 0);
			json_kv_bool(out, 5, "is_anomaly", pis_anomaly, 0);
			json_kv_str(out, 5, "subtype", ptype, 0);
			json_kv_str(out, 5, "root_cause", proot_cause, 0);
			json_kv_str(out, 5, "suggestion", psuggestion, 0);

			snprintf(buf, sizeof(buf), "%s +%.0fs", ts, duration_s);
			json_kv_str(out, 5, "time_window", buf, 0);

			json_obj_begin(out, 5, "key_metrics");
			char kmbuf[128];
			snprintf(kmbuf, sizeof(kmbuf), "%llu (%.0f/s)", p->total_count, rate);
			json_kv_str(out, 6, "系统调用总数", kmbuf, 0);
			snprintf(kmbuf, sizeof(kmbuf), "%.0f us", avg_us);
			json_kv_str(out, 6, "平均耗时", kmbuf, 0);
			snprintf(kmbuf, sizeof(kmbuf), "%llu 次", p->top_nr_count);
			json_kv_str(out, 6, "最多调用", kmbuf, 0);
			snprintf(kmbuf, sizeof(kmbuf), "%s (%.1f ms)",
				syscall_name(p->top_lat_nr), (double)p->top_lat_ns / 1e6);
			json_kv_str(out, 6, "耗时最多", kmbuf, 1);
			json_obj_end(out, 5, 0);

			fprintf(out, "            \"evidence\": [\n");
			if (avg_us > g_cfg.hot_lat_us)
				fprintf(out, "              \"TID %u (%s): %llu 次系统调用 (%.0f/s), 平均耗时 %.0f us (阈值 %d us), 耗时最多 %s (%.1fms)\"\n",
					p->tid, p->comm, p->total_count, rate, avg_us, g_cfg.hot_lat_us,
					syscall_name(p->top_lat_nr), (double)p->top_lat_ns / 1e6);
			else
				fprintf(out, "              \"TID %u (%s): %llu 次系统调用 (%.0f/s, 阈值 %d/s), 最多调用 %s (%llu次)\"\n",
					p->tid, p->comm, p->total_count, rate, g_cfg.hot_freq_per_sec,
					syscall_name(p->top_nr), p->top_nr_count);
			fprintf(out, "            ]\n");
			pdiag++;
			json_obj_end(out, 4, 1);
		}

			if (diag == 0 && pdiag == 0) {
				json_indent(out, 4);
				fprintf(out, "{\n");
				json_kv_str(out, 5, "target", "系统调用", 0);
				json_kv_bool(out, 5, "is_anomaly", 0, 0);
				json_kv_str(out, 5, "subtype", "正常", 0);
				json_kv_str(out, 5, "root_cause", "未检测到明显热点", 0);
				json_kv_str(out, 5, "suggestion", "当前系统调用指标在正常范围内", 0);

				snprintf(buf, sizeof(buf), "%s +%.0fs", ts, duration_s);
				json_kv_str(out, 5, "time_window", buf, 0);

				json_obj_begin(out, 5, "key_metrics");
				snprintf(buf, sizeof(buf), "%llu (%.0f/s)", grand_total, (double)grand_total / duration_s);
				json_kv_str(out, 6, "总调用数", buf, 0);
				snprintf(buf, sizeof(buf), "%.1fms", (double)grand_ns / 1e6);
				json_kv_str(out, 6, "总耗时", buf, 0);
				snprintf(buf, sizeof(buf), "%llu (%.1f%%)", grand_err, grand_total > 0 ? (double)grand_err / grand_total * 100.0 : 0);
				json_kv_str(out, 6, "错误数", buf, 1);
				json_obj_end(out, 5, 0);

				fprintf(out, "            \"evidence\": [\n");
				fprintf(out, "              \"所有系统调用频率、耗时、错误率均在正常阈值范围内\"\n");
				fprintf(out, "            ]\n");
				fprintf(out, "          }");
			}
		fprintf(out, "\n");
		json_arr_end(out, 3, 1);
		json_obj_end(out, 2, 1);
	}

	json_arr_end(out, 1, 1);
	fprintf(out, "}\n");
	json_close(out);
	fprintf(stderr, "[*] JSON 报告已写入 %s\n", path);
}

static void usage(const char *prog)
{
	fprintf(stderr,
		"用法: %s [选项]\n"
		"\n"
		"系统调用热点观测工具 —— 基于 eBPF 追踪所有系统调用，\n"
		"识别高频、高耗时及高错误率的系统调用热点。\n"
		"\n"
		"选项:\n"
		"  -i, --interval <秒>      采样间隔（默认: %d）\n"
		"  -d, --duration <秒>      总运行时长，0 表示持续运行（默认: 0）\n"
		"  -o, --output <文件路径>  输出到文件（默认: 标准输出）\n"
		"  -j, --json               输出 JSON + Markdown 报告到 report/ 目录\n"
		"  -h, --help               显示本帮助信息\n"
		"\n"
		"示例:\n"
		"  sudo %s                       # 默认参数运行\n"
		"  sudo %s -i 3 -d 60            # 每 3 秒采样，运行 60 秒\n"
		"  sudo %s -j -d 30              # 输出 JSON 诊断报告\n",
		prog, g_cfg.interval, prog, prog, prog);
}

int run_syscall(int argc, char **argv)
{
	int interval = g_cfg.interval;
	int duration = 0;
	int json_output = 0;
	const char *output_file = NULL;

	static struct option long_opts[] = {
		{"interval", required_argument, 0, 'i'},
		{"duration", required_argument, 0, 'd'},
		{"output",   required_argument, 0, 'o'},
		{"json",     no_argument,       0, 'j'},
		{"help",     no_argument,       0, 'h'},
		{0, 0, 0, 0}
	};

	int opt;
	while ((opt = getopt_long(argc, argv, "i:d:o:jh", long_opts, NULL)) != -1) {
		switch (opt) {
		case 'i': interval = atoi(optarg); break;
		case 'd': duration = atoi(optarg); break;
		case 'o': output_file = optarg; break;
		case 'j': json_output = 1; break;
		case 'h': usage(argv[0]); return 0;
		default:  usage(argv[0]); return 1;
		}
	}

	if (check_interval(interval) != 0)
		return 1;

	FILE *out = open_output(output_file);
	if (!out)
		return 1;

	libbpf_set_print(NULL);
	signal(SIGINT, on_signal);
	signal(SIGTERM, on_signal);

	struct syscall_anomaly_bpf *skel = syscall_anomaly_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "无法加载 BPF 程序 (需要 root 权限)\n");
		if (output_file) fclose(out);
		return 1;
	}
	if (syscall_anomaly_bpf__attach(skel) != 0) {
		fprintf(stderr, "无法挂载 BPF 程序\n");
		syscall_anomaly_bpf__destroy(skel);
		if (output_file) fclose(out);
		return 1;
	}

	int sys_stats_fd   = bpf_map__fd(skel->maps.sys_stats);
	int pid_nr_stats_fd = bpf_map__fd(skel->maps.pid_nr_stats);

	fprintf(stderr, "[*] 系统调用热点观测已启动, 采样间隔=%ds\n", interval);

	time_t start = time(NULL);

	while (!exiting) {
		sleep(interval);
		unsigned long long interval_ns = (unsigned long long)interval * 1000000000ULL;

		struct syscall_entry *entries = NULL;
		int n = 0;
		if (collect_sys_stats(sys_stats_fd, &entries, &n) != 0)
			break;

		struct pid_summary *pids = NULL;
		int pn = 0;
		if (collect_pid_summary(pid_nr_stats_fd, &pids, &pn) != 0) {
			free(entries);
			break;
		}

		print_report(out, entries, n, pids, pn, interval_ns);

		if (exiting || (duration > 0 && time(NULL) - start >= duration)) {
			if (json_output) {
				print_syscall_json_report(entries, n, pids, pn, interval_ns);
				json_to_markdown("report/hot.json", "report/hot.md");
			}
		}

		free(entries);
		free(pids);

		if (exiting || (duration > 0 && time(NULL) - start >= duration))
			break;

		reset_map(sys_stats_fd);
		reset_u64_map(pid_nr_stats_fd);
	}

	fprintf(stderr, "[*] 正在退出...\n");
	syscall_anomaly_bpf__destroy(skel);
	if (output_file) fclose(out);
	return 0;
}
