// lock_anomaly.c — 锁竞争异常观测与根因定位 (用户态)
//
// 双 skeleton 架构:
//   - cpu_anomaly_bpf:  提供 sched_switch / sched_stat_blocked / on-CPU 数据
//   - lock_anomaly_bpf: 提供 futex per-key 热点锁 + 等待点调用栈
//
// 用法:
//   eebpf lock [-i interval_s] [-d duration_s] [-o output_file] [-p profile_hz] [-j]

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <getopt.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <linux/perf_event.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <sys/utsname.h>
#include "../include/utils.h"
#include "../include/report_json.h"
#include "../include/report_md.h"
#include "cpu_anomaly.skel.h"
#include "lock_anomaly.skel.h"
#include "../include/lock_anomaly.h"
#include "../include/common.h"
#include "../include/config.h"

// 配置常量
#define HOT_KEY_RATIO          0.5      // 单键占比 > 50% = 热点锁

// cpu_anomaly 的 pid_stats
struct cpu_pid_stats {
	unsigned long long on_cpu_ns;
	unsigned long long cswitch_total;
	unsigned long long cswitch_voluntary;
	unsigned long long cswitch_involuntary;
	unsigned long long wakeup_count;
	unsigned long long total_sched_delay_ns;
	unsigned long long max_sched_delay_ns;
	unsigned long long wait_ns;
	unsigned long long sleep_ns;
	unsigned long long blocked_ns;
	unsigned long long migrate_count;
	unsigned long long futex_wait_ns;
	unsigned long long futex_wait_count;
	unsigned long long cpu_runtime_ns;
};

// lock_anomaly 的结构体
struct futex_key {
	unsigned int tgid;
	unsigned long long uaddr;
};

struct futex_hot_stats {
	unsigned long long wait_ns;
	unsigned long long wait_count;
	unsigned long long max_wait_ns;
};

struct lock_pid_stats {
	unsigned long long futex_wait_ns;
	unsigned long long futex_wait_count;
	unsigned long long futex_max_wait_ns;
};


// 进程信息
struct lock_proc_info {
	unsigned int pid;
	char comm[16];
	struct cpu_pid_stats cpu;
	struct lock_pid_stats lock;
};

// 栈条目
struct stack_entry {
	int stack_id;
	unsigned long long count;
};

// 读取 /proc/<tid>/status 获取 Tgid (线程组 ID)
static unsigned int get_tgid(unsigned int tid)
{
	char path[64], line[256];
	unsigned int tgid = tid; // fallback
	snprintf(path, sizeof(path), "/proc/%u/status", tid);
	FILE *f = fopen(path, "r");
	if (f) {
		while (fgets(line, sizeof(line), f)) {
			if (sscanf(line, "Tgid:\t%u", &tgid) == 1)
				break;
		}
		fclose(f);
	}
	return tgid;
}

// 收集 CPU skeleton 中有锁相关活动的进程
static int collect_lock_procs(int cpu_stats_fd, int lock_stats_fd,
                              struct lock_proc_info **out, int *out_count)
{
	int capacity = 256, count = 0;
	*out = malloc(capacity * sizeof(struct lock_proc_info));
	if (!*out) return -1;

	// 遍历 lock_pid_stats (有 futex 活动的线程)
	unsigned int key = 0, next_key;
	while (bpf_map_get_next_key(lock_stats_fd, &key, &next_key) == 0) {
		struct lock_pid_stats lval = {};
		if (bpf_map_lookup_elem(lock_stats_fd, &next_key, &lval) != 0) {
			key = next_key;
			continue;
		}
		if (lval.futex_wait_count == 0) { key = next_key; continue; }

		if (count >= capacity) {
			capacity *= 2;
			*out = realloc(*out, capacity * sizeof(struct lock_proc_info));
			if (!*out) return -1;
		}

		struct lock_proc_info *p = &(*out)[count];
		memset(p, 0, sizeof(*p));
		p->pid = next_key;
		p->lock = lval;
		read_comm(next_key, p->comm, sizeof(p->comm));

		// 补充 CPU skeleton 数据
		struct cpu_pid_stats cval = {};
		bpf_map_lookup_elem(cpu_stats_fd, &next_key, &cval);
		p->cpu = cval;

		count++;
		key = next_key;
	}

	*out_count = count;
	return 0;
}

// 收集热点锁 (futex_key_stats)
struct hot_lock_entry {
	struct futex_key key;
	struct futex_hot_stats stats;
};

static int cmp_hot_lock(const void *a, const void *b)
{
	const struct hot_lock_entry *ha = a, *hb = b;
	return (hb->stats.wait_ns > ha->stats.wait_ns) -
	       (ha->stats.wait_ns > hb->stats.wait_ns);
}

static int collect_hot_locks(int hot_fd, struct hot_lock_entry **out, int *out_count)
{
	int capacity = 256, count = 0;
	*out = malloc(capacity * sizeof(struct hot_lock_entry));
	if (!*out) return -1;

	struct futex_key key = {}, next_key;
	while (bpf_map_get_next_key(hot_fd, &key, &next_key) == 0) {
		struct futex_hot_stats val = {};
		if (bpf_map_lookup_elem(hot_fd, &next_key, &val) != 0) {
			key = next_key;
			continue;
		}
		if (val.wait_count == 0) { key = next_key; continue; }

		if (count >= capacity) {
			capacity *= 2;
			*out = realloc(*out, capacity * sizeof(struct hot_lock_entry));
			if (!*out) return -1;
		}

		(*out)[count].key = next_key;
		(*out)[count].stats = val;
		count++;
		key = next_key;
	}

	qsort(*out, count, sizeof(struct hot_lock_entry), cmp_hot_lock);
	*out_count = count;
	return 0;
}

// 收集栈采样 (lock_stack_counts)
static int collect_lock_stacks(int counts_fd, struct stack_entry **out,
                               int *out_count, unsigned long long *total)
{
	int capacity = 256, count = 0;
	*out = malloc(capacity * sizeof(struct stack_entry));
	if (!*out) return -1;
	*total = 0;

	unsigned int key = 0, next_key;
	while (bpf_map_get_next_key(counts_fd, &key, &next_key) == 0) {
		unsigned long long val = 0;
		if (bpf_map_lookup_elem(counts_fd, &next_key, &val) != 0) {
			key = next_key;
			continue;
		}
		*total += val;
		if (count >= capacity) {
			capacity *= 2;
			*out = realloc(*out, capacity * sizeof(struct stack_entry));
			if (!*out) return -1;
		}
		(*out)[count].stack_id = (int)next_key;
		(*out)[count].count = val;
		count++;
		key = next_key;
	}
	*out_count = count;
	return 0;
}

static int cmp_stack(const void *a, const void *b)
{
	const struct stack_entry *sa = a, *sb = b;
	return (sb->count > sa->count) - (sa->count > sb->count);
}

static void print_call_stack(FILE *out, int stackmap_fd, int stack_id,
                             int resolve_pid, const char *prefix)
{
	unsigned long long ips[127];
	memset(ips, 0, sizeof(ips));
	if (bpf_map_lookup_elem(stackmap_fd, &stack_id, ips) != 0) {
		fprintf(out, "%s  (无法读取栈数据)\n", prefix);
		return;
	}
	int depth = 0;
	for (int i = 0; i < 127 && ips[i] != 0; i++) depth++;
	if (depth == 0) {
		fprintf(out, "%s  (无用户态栈)\n", prefix);
		return;
	}
	for (int i = 0; i < depth; i++) {
		char sym[256];
		resolve_ip(resolve_pid, ips[i], sym, sizeof(sym));
		fprintf(out, "%s  #%-2d  %s\n", prefix, i, sym);
	}
}

// 文本诊断报告
static void print_lock_report(FILE *out,
                              struct lock_proc_info *procs, int count,
                              struct hot_lock_entry *hot_locks, int hot_count,
                              struct stack_entry *stacks, int stack_count,
                              unsigned long long total_stacks,
                              int stackmap_fd, int ncpu,
                              unsigned long long interval_ns)
{
	char ts[32];
	iso_timestamp(ts, sizeof(ts));
	double duration_s = (double)interval_ns / 1e9;
	struct sys_metrics sys;
	read_sys_metrics(&sys);

	// 汇总统计
	unsigned long long total_futex_waits = 0, total_futex_ns = 0;
	for (int i = 0; i < count; i++) {
		total_futex_waits += procs[i].lock.futex_wait_count;
		total_futex_ns += procs[i].lock.futex_wait_ns;
	}
	double global_avg_wait_us = total_futex_waits > 0
		? (double)total_futex_ns / (double)total_futex_waits / 1000.0 : 0;

	fprintf(out,
		"======================================================================\n"
		"  锁竞争异常观测诊断报告\n"
		"======================================================================\n"
		"  异常时间窗口: %s  (采样间隔 %.1fs)\n"
		"----------------------------------------------------------------------\n"
		"  系统概览\n"
		"  CPU 核心数: %-4d   活跃锁竞争进程: %d\n"
		"  系统负载:       1min %.2f   5min %.2f   15min %.2f\n"
		"  全局 futex 等待: %llu 次  |  平均等待: %.0fus  |  总等待: %.1fms\n"
		"======================================================================\n\n",
		ts, duration_s, ncpu, count,
		sys.load1, sys.load5, sys.load15,
		total_futex_waits, global_avg_wait_us,
		(double)total_futex_ns / 1e6);

	// 热点锁 TOP 10
	if (hot_count > 0) {
		fprintf(out,
			"──────────────────────────────────────────────────────────────────────\n"
			"  热点锁 Top-%d (按总等待时间排序)\n"
			"──────────────────────────────────────────────────────────────────────\n\n",
			hot_count < 10 ? hot_count : 10);

		for (int i = 0; i < hot_count && i < 10; i++) {
			struct futex_hot_stats *hs = &hot_locks[i].stats;
			double avg_us = hs->wait_count > 0
				? (double)hs->wait_ns / (double)hs->wait_count / 1000.0 : 0;
			double max_us = (double)hs->max_wait_ns / 1000.0;
			fprintf(out,
				"  [%d] TGID %u  uaddr=0x%llx\n"
				"      等待次数: %llu  |  总等待: %.1fms  |  avg: %.0fus  |  max: %.0fus\n\n",
				i + 1, hot_locks[i].key.tgid,
				(unsigned long long)hot_locks[i].key.uaddr,
				hs->wait_count, (double)hs->wait_ns / 1e6,
				avg_us, max_us);
		}

		// 集中度判定
		if (hot_count > 0 && total_futex_ns > 0) {
			double top1_ratio = (double)hot_locks[0].stats.wait_ns /
			                    (double)total_futex_ns;
			fprintf(out, "  锁集中度: Top-1 热点锁占总等待时间 %.1f%%\n", top1_ratio * 100);
			if (top1_ratio > HOT_KEY_RATIO)
				fprintf(out, "  >> 存在严重热点锁 — 单锁集中度 > %.0f%%\n", HOT_KEY_RATIO * 100);
			fprintf(out, "\n");
		}
	}

	// 等待点调用栈
	if (total_stacks > 0 && stack_count > 0) {
		qsort(stacks, stack_count, sizeof(struct stack_entry), cmp_stack);
		fprintf(out,
			"──────────────────────────────────────────────────────────────────────\n"
			"  锁等待点调用栈 Top-5 (futex_wait 发生时采样)\n"
			"──────────────────────────────────────────────────────────────────────\n\n");
		int top_n = stack_count < 5 ? stack_count : 5;
		int resolve_pid = count > 0 ? (int)procs[0].pid : 0;
		for (int i = 0; i < top_n; i++) {
			fprintf(out, "  #%d  stack_id=%d  采样 %llu 次 (%.1f%%)\n",
			        i + 1, stacks[i].stack_id, stacks[i].count,
			        (double)stacks[i].count / (double)total_stacks * 100.0);
			if (stackmap_fd >= 0)
				print_call_stack(out, stackmap_fd, stacks[i].stack_id,
				                 resolve_pid, "    ");
			fprintf(out, "\n");
		}
	}

	// 逐进程诊断
	int seq = 0;
	int anomaly_count = 0;

	for (int i = 0; i < count; i++) {
		struct lock_pid_stats *ls = &procs[i].lock;
		struct cpu_pid_stats *cs = &procs[i].cpu;

		double futex_avg_us = ls->futex_wait_count > 0
			? (double)ls->futex_wait_ns / (double)ls->futex_wait_count / 1000.0 : 0;
		double futex_max_us = (double)ls->futex_max_wait_ns / 1000.0;
		double cpu_pct = (double)cs->on_cpu_ns / (double)interval_ns * 100.0;
		double cswitch_pm = cs->cswitch_total > 0
			? (double)cs->cswitch_total / ((double)interval_ns / 60e9) : 0;
		double vol_ratio = cs->cswitch_total > 0
			? (double)cs->cswitch_voluntary / (double)cs->cswitch_total : 0;
		double blocked_ms = (double)cs->blocked_ns / 1e6;

		// 判定异常
		int is_anomaly = 0;
		const char *subtype = NULL;
		const char *root_cause = NULL;
		const char *suggestion = NULL;
		char evidence[6][256];
		int ev_count = 0;

		// 获取 TGID 匹配热点锁
		unsigned int tgid = get_tgid(procs[i].pid);
		int proc_hot_keys = 0;
		unsigned long long proc_hot_max_ns = 0;
		for (int h = 0; h < hot_count; h++) {
			if (hot_locks[h].key.tgid == tgid) {
				proc_hot_keys++;
				if (hot_locks[h].stats.wait_ns > proc_hot_max_ns) proc_hot_max_ns = hot_locks[h].stats.wait_ns;
			}
		}

		// 非竞争性 futex 等待: 次数很少 + 长时间等待 = 事件睡眠, 非锁竞争
		int is_parked = (ls->futex_wait_count <= 3 &&
		                 futex_avg_us > g_cfg.lock_futex_crit_us &&
		                 cswitch_pm < 5000);

		if (is_parked) {
			snprintf(evidence[ev_count++], sizeof(evidence[0]),
			         "futex 等待 %llu 次, avg %.0fus — 属正常事件等待/线程睡眠，非锁竞争",
			         ls->futex_wait_count, futex_avg_us);
		}

		// 临界区过大: 多次等待 + avg > 50ms
		if (!is_anomaly && !is_parked &&
		    ls->futex_wait_count > 5 && futex_avg_us > g_cfg.lock_futex_crit_us) {
			is_anomaly = 1;
			subtype = "锁竞争 (临界区过大)";
			root_cause = "多次 futex 等待时间过长，临界区代码执行耗时严重";
			suggestion = "使用 perf lock 分析锁持有时间；"
			             "审查临界区代码复杂度，考虑拆分或异步化";
			snprintf(evidence[ev_count++], sizeof(evidence[0]),
			         "futex 等待 %llu 次, avg %.0fus 超过严重阈值 %dus, max %.0fus",
			         ls->futex_wait_count, futex_avg_us, g_cfg.lock_futex_crit_us, futex_max_us);
		}

		// 热点锁集中争用: 单键占比 > 50%
		if (!is_anomaly && !is_parked && proc_hot_keys >= 2 &&
		    proc_hot_max_ns > (unsigned long long)((double)ls->futex_wait_ns * HOT_KEY_RATIO)) {
			is_anomaly = 1;
			subtype = "锁竞争 (热点锁集中)";
			root_cause = "多线程争用同一临界区，热点锁集中度过高";
			suggestion = "审查热点锁的临界区粒度；考虑锁拆分、"
			             "读写锁 (rwlock) 或无锁数据结构";
			snprintf(evidence[ev_count++], sizeof(evidence[0]),
			         "TGID %u 内 %d 个热点锁占总 futex 等待 %.0f%%",
			         tgid, proc_hot_keys,
			         (double)proc_hot_max_ns / (double)ls->futex_wait_ns * 100.0);
		}

		// 锁粒度过粗: 高主动切换 + futex 等待
		if (!is_anomaly && !is_parked && vol_ratio > VOLUNTARY_RATIO_HIGH &&
		    cswitch_pm > 10000 && ls->futex_wait_count > 3) {
			is_anomaly = 1;
			subtype = "锁竞争 (锁粒度过粗)";
			root_cause = "主动切换占比高 + futex 等待显著，"
			             "线程频繁因锁等待让出 CPU";
			suggestion = "检查线程池与锁的配比；考虑减小锁粒度或分段锁";
			snprintf(evidence[ev_count++], sizeof(evidence[0]),
			         "主动切换占比 %.0f%% (%.0f/min)，futex 等待 %llu 次, avg %.0fus",
			         vol_ratio * 100, (double)cs->cswitch_voluntary /
			         ((double)interval_ns / 60e9),
			         ls->futex_wait_count, futex_avg_us);
		}

		// 一般锁竞争: avg > 10ms + 多次等待
		if (!is_anomaly && !is_parked &&
		    ls->futex_wait_count > 3 && futex_avg_us > g_cfg.lock_futex_warn_us) {
			is_anomaly = 1;
			subtype = "锁竞争";
			root_cause = "futex 等待时间偏高，存在锁竞争导致性能退化";
			suggestion = "使用 perf lock 分析锁热点；"
			             "排查 futex 等待模式及线程同步策略";
			snprintf(evidence[ev_count++], sizeof(evidence[0]),
			         "futex 等待 %llu 次, avg %.0fus 超过警告阈值 %dus",
			         ls->futex_wait_count, futex_avg_us, g_cfg.lock_futex_warn_us);
		}

		// 补充通用证据
		if (is_anomaly) {
			anomaly_count++;
			snprintf(evidence[ev_count++], sizeof(evidence[0]),
			         "CPU 占用 %.1f%%, 阻塞时间 %.1fms",
			         cpu_pct, blocked_ms);
			if (cs->blocked_ns > (unsigned long long)g_cfg.lock_blocked_warn_ms * 1000000ULL)
				snprintf(evidence[ev_count++], sizeof(evidence[0]),
				         "阻塞时间 %.1fms 偏高 — 线程大量时间消耗在等待",
				         blocked_ms);
		}

		seq++;
		const char *status_icon = is_anomaly ? "!!" : (is_parked ? "--" : "OK");
		fprintf(out,
			"──────────────────────────────────────────────────────────────────────\n"
			"  [%d] PID %-6u  %-16s  状态: %s",
			seq, procs[i].pid, procs[i].comm, status_icon);
		if (is_anomaly && subtype)
			fprintf(out, "  %s", subtype);
		else if (is_parked)
			fprintf(out, "  futex 长期等待 (事件睡眠)");
		fprintf(out, "\n"
			"──────────────────────────────────────────────────────────────────────\n\n");

		fprintf(out,
			"  关键指标:\n"
			"    futex 等待次数:      %llu\n"
			"    futex 平均等待:      %6.0f us\n"
			"    futex 最大等待:      %6.0f us\n"
			"    futex 总等待时间:    %6.1f ms\n"
			"    阻塞时间 (sched):    %6.1f ms\n"
			"    CPU 占用:           %6.1f%%\n"
			"    上下文切换:         %6.0f/min  (主动: %llu)\n"
			"    主动切换占比:       %6.0f%%\n",
			ls->futex_wait_count, futex_avg_us, futex_max_us,
			(double)ls->futex_wait_ns / 1e6,
			blocked_ms,
			cpu_pct, cswitch_pm, cs->cswitch_voluntary,
			vol_ratio * 100.0);

		if (proc_hot_keys > 0) {
			fprintf(out, "    关联热点锁:          %d 个\n", proc_hot_keys);
			for (int h = 0; h < hot_count && h < 5; h++) {
				if (hot_locks[h].key.tgid == tgid) {
					double havg = hot_locks[h].stats.wait_count > 0
						? (double)hot_locks[h].stats.wait_ns /
						  (double)hot_locks[h].stats.wait_count / 1000.0 : 0;
					fprintf(out,
						"      uaddr=0x%llx  wait=%llu  avg=%.0fus\n",
						(unsigned long long)hot_locks[h].key.uaddr,
						hot_locks[h].stats.wait_count, havg);
				}
			}
		}
		fprintf(out, "\n");

		if (is_anomaly && ev_count > 0) {
			fprintf(out, "  诊断证据:\n");
			for (int e = 0; e < ev_count; e++)
				fprintf(out, "    • %s\n", evidence[e]);
			fprintf(out, "\n");
			if (root_cause)
				fprintf(out, "  疑似根因: %s\n", root_cause);
			if (suggestion)
				fprintf(out, "  建议:     %s\n", suggestion);
			fprintf(out, "\n");
		}
	}

	if (seq == 0)
		fprintf(out, "  (未检测到 futex 锁活动)\n\n");

	if (anomaly_count == 0 && seq > 0)
		fprintf(out, "  (当前 futex 等待指标在正常范围内)\n\n");

	fprintf(out, "======================================================================\n\n");
	fflush(out);
}

// JSON 报告 (统一 schema)
static void print_json_report(struct lock_proc_info *procs, int count,
                              struct hot_lock_entry *hot_locks, int hot_count,
                              struct stack_entry *stacks, int stack_count,
                              unsigned long long total_stacks,
                              int stackmap_fd, unsigned long long interval_ns)
{
	const char *path = "report/lock.json";
	FILE *out = json_open(path);
	if (!out) return;

	char ts[32];
	iso_timestamp(ts, sizeof(ts));
	double duration_s = (double)interval_ns / 1e9;
	struct sys_metrics sys;
	read_sys_metrics(&sys);

	unsigned long long total_futex_waits = 0, total_futex_ns = 0;
	for (int i = 0; i < count; i++) {
		total_futex_waits += procs[i].lock.futex_wait_count;
		total_futex_ns += procs[i].lock.futex_wait_ns;
	}
	double global_avg_us = total_futex_waits > 0
		? (double)total_futex_ns / (double)total_futex_waits / 1000.0 : 0;

	fprintf(out, "{\n");
	json_kv_str(out, 1, "module", "lock", 0);
	json_kv_str(out, 1, "timestamp", ts, 0);
	json_kv_double(out, 1, "duration_s", duration_s, "%.1f", 0);

	// system
	char buf[256];
	json_obj_begin(out, 1, "system");
	snprintf(buf, sizeof(buf), "%llu 次", total_futex_waits);
	json_kv_str(out, 2, "全局 futex 等待次数", buf, 0);
	snprintf(buf, sizeof(buf), "%.0fus", global_avg_us);
	json_kv_str(out, 2, "全局平均 futex 等待", buf, 0);
	snprintf(buf, sizeof(buf), "%.1fms", (double)total_futex_ns / 1e6);
	json_kv_str(out, 2, "全局 futex 总等待时间", buf, 0);
	snprintf(buf, sizeof(buf), "%.2f / %.2f / %.2f",
		 sys.load1, sys.load5, sys.load15);
	json_kv_str(out, 2, "系统负载 (1m/5m/15m)", buf, 0);
	snprintf(buf, sizeof(buf), "%d", count);
	json_kv_str(out, 2, "活跃锁竞争进程数", buf, 1);
	json_obj_end(out, 1, 0);

	json_arr_begin(out, 1, "sections");

	// section: hot locks table
	if (hot_count > 0) {
		json_obj_begin_nokey(out, 2);
		json_kv_str(out, 3, "type", "table", 0);
		json_kv_str(out, 3, "title", "热点锁 Top-10", 0);
		fprintf(out, "          \"columns\": [\"排名\", \"TGID\", \"uaddr\", \"等待次数\", \"总等待\", \"avg\", \"max\"],\n");
		json_arr_begin(out, 3, "rows");
		int hl = hot_count < 10 ? hot_count : 10;
		for (int i = 0; i < hl; i++) {
			struct futex_hot_stats *hs = &hot_locks[i].stats;
			double avg_us = hs->wait_count > 0
				? (double)hs->wait_ns / (double)hs->wait_count / 1000.0 : 0;
			json_indent(out, 4);
			fprintf(out, "[\"%d\", \"%u\", \"0x%llx\", \"%llu\", \"%.1fms\", \"%.0fus\", \"%.0fus\"]%s\n",
				i + 1, hot_locks[i].key.tgid,
				(unsigned long long)hot_locks[i].key.uaddr,
				hs->wait_count, (double)hs->wait_ns / 1e6,
				avg_us, (double)hs->max_wait_ns / 1000.0,
				i < hl - 1 ? "," : "");
		}
		json_arr_end(out, 3, 1);
		json_obj_end(out, 2, 0);
	}

	// section: diagnosis
	{
		json_obj_begin_nokey(out, 2);
		json_kv_str(out, 3, "type", "diagnosis", 0);
		json_kv_str(out, 3, "title", "锁竞争诊断分析", 0);
		json_arr_begin(out, 3, "findings");

		int diag = 0;
		for (int i = 0; i < count && i < 20; i++) {
			struct lock_pid_stats *ls = &procs[i].lock;
			struct cpu_pid_stats *cs = &procs[i].cpu;
			double futex_avg_us = ls->futex_wait_count > 0
				? (double)ls->futex_wait_ns / (double)ls->futex_wait_count / 1000.0 : 0;
			double futex_max_us = (double)ls->futex_max_wait_ns / 1000.0;
			double cpu_pct = (double)cs->on_cpu_ns / (double)interval_ns * 100.0;
			double cswitch_pm = cs->cswitch_total > 0
				? (double)cs->cswitch_total / ((double)interval_ns / 60e9) : 0;
			double vol_ratio = cs->cswitch_total > 0
				? (double)cs->cswitch_voluntary / (double)cs->cswitch_total : 0;
			double blocked_ms = (double)cs->blocked_ns / 1e6;

			unsigned int tgid = get_tgid(procs[i].pid);
			int proc_hot_keys = 0;
			unsigned long long proc_hot_max_ns = 0;
			for (int h = 0; h < hot_count; h++) {
				if (hot_locks[h].key.tgid == tgid) {
					proc_hot_keys++;
					if (hot_locks[h].stats.wait_ns > proc_hot_max_ns)
						proc_hot_max_ns = hot_locks[h].stats.wait_ns;
				}
			}

			int is_parked = (ls->futex_wait_count <= 3 &&
			                 futex_avg_us > g_cfg.lock_futex_crit_us &&
			                 cswitch_pm < 5000);
			int is_anomaly = 0;
			const char *subtype = NULL;
			const char *root_cause = NULL;
			const char *suggestion = NULL;

			if (is_parked) {
				subtype = "futex 长期等待 (事件睡眠)";
			} else if (ls->futex_wait_count > 5 && futex_avg_us > g_cfg.lock_futex_crit_us) {
				is_anomaly = 1;
				subtype = "锁竞争 (临界区过大)";
				root_cause = "多次 futex 等待时间过长，临界区代码执行耗时严重";
				suggestion = "使用 perf lock 分析锁持有时间；审查临界区代码复杂度，考虑拆分或异步化";
			} else if (proc_hot_keys >= 2 &&
			           proc_hot_max_ns > (unsigned long long)((double)ls->futex_wait_ns * HOT_KEY_RATIO)) {
				is_anomaly = 1;
				subtype = "锁竞争 (热点锁集中)";
				root_cause = "多线程争用同一临界区，热点锁集中度过高";
				suggestion = "审查热点锁的临界区粒度；考虑锁拆分、读写锁 (rwlock) 或无锁数据结构";
			} else if (vol_ratio > VOLUNTARY_RATIO_HIGH &&
			           cswitch_pm > 10000 && ls->futex_wait_count > 3) {
				is_anomaly = 1;
				subtype = "锁竞争 (锁粒度过粗)";
				root_cause = "主动切换占比高 + futex 等待显著，线程频繁因锁等待让出 CPU";
				suggestion = "检查线程池与锁的配比；考虑减小锁粒度或分段锁";
			} else if (ls->futex_wait_count > 3 && futex_avg_us > g_cfg.lock_futex_warn_us) {
				is_anomaly = 1;
				subtype = "锁竞争";
				root_cause = "futex 等待时间偏高，存在锁竞争导致性能退化";
				suggestion = "使用 perf lock 分析锁热点；排查 futex 等待模式及线程同步策略";
			}

			if (diag > 0) fprintf(out, ",\n");
			json_indent(out, 4);
			fprintf(out, "{\n");
			snprintf(buf, sizeof(buf), "%s(%u)", procs[i].comm, procs[i].pid);
			json_kv_str(out, 5, "target", buf, 0);
			json_kv_bool(out, 5, "is_anomaly", is_anomaly, 0);
			json_kv_str(out, 5, "subtype", subtype ? subtype : (is_parked ? "futex 长期等待" : "正常"), 0);
			json_kv_str(out, 5, "root_cause", root_cause ? root_cause : "", 0);
			json_kv_str(out, 5, "suggestion", suggestion ? suggestion : "", 0);

			json_obj_begin(out, 5, "key_metrics");
			snprintf(buf, sizeof(buf), "%llu 次", ls->futex_wait_count);
			json_kv_str(out, 6, "futex 等待次数", buf, 0);
			snprintf(buf, sizeof(buf), "%.0fus", futex_avg_us);
			json_kv_str(out, 6, "futex 平均等待", buf, 0);
			snprintf(buf, sizeof(buf), "%.0fus", futex_max_us);
			json_kv_str(out, 6, "futex 最大等待", buf, 0);
			snprintf(buf, sizeof(buf), "%.1fms", (double)ls->futex_wait_ns / 1e6);
			json_kv_str(out, 6, "futex 总等待时间", buf, 0);
			snprintf(buf, sizeof(buf), "%.1fms", blocked_ms);
			json_kv_str(out, 6, "阻塞时间", buf, 0);
			snprintf(buf, sizeof(buf), "%.1f%%", cpu_pct);
			json_kv_str(out, 6, "CPU 占用", buf, 0);
			snprintf(buf, sizeof(buf), "%.0f/min (主动: %llu)", cswitch_pm, cs->cswitch_voluntary);
			json_kv_str(out, 6, "上下文切换", buf, 1);
			json_obj_end(out, 5, 1);

			diag++;
			json_obj_end(out, 4, 1);
		}

		json_arr_end(out, 3, 1);
		json_obj_end(out, 2, 0);
	}

	// section: stacks (wait point call stacks)
	if (total_stacks > 0 && stack_count > 0) {
		json_obj_begin_nokey(out, 2);
		json_kv_str(out, 3, "type", "stacks", 0);
		json_kv_str(out, 3, "title", "锁等待点调用栈", 0);
		fprintf(out, "          \"total_samples\": %llu,\n", total_stacks);

		int resolve_pid = count > 0 ? (int)procs[0].pid : 0;
		int top_n = stack_count < 5 ? stack_count : 5;

		fprintf(out, "          \"top_stacks\": [\n");
		for (int i = 0; i < top_n; i++) {
			double pct = (double)stacks[i].count / (double)total_stacks * 100.0;

			json_indent(out, 4);
			fprintf(out, "{\n");
			json_kv_int(out, 5, "rank", i + 1, 0);
			json_kv_int(out, 5, "count", (int)stacks[i].count, 0);
			json_kv_double(out, 5, "pct", pct, "%.1f", 0);

			__u64 ips[127];
			memset(ips, 0, sizeof(ips));
			int depth = 0;
			if (stackmap_fd >= 0 &&
			    bpf_map_lookup_elem(stackmap_fd, &stacks[i].stack_id, ips) == 0) {
				for (int j = 0; j < 127 && ips[j] != 0; j++) depth++;
			}

			fprintf(out, "            \"frames\": [\n");
			for (int j = 0; j < depth; j++) {
				char sym[256];
				resolve_ip(resolve_pid, ips[j], sym, sizeof(sym));
				json_indent(out, 6);
				fprintf(out, "\"%s\"%s\n", sym, j < depth - 1 ? "," : "");
			}
			if (depth == 0) {
				json_indent(out, 6);
				fprintf(out, "\"(empty)\"");
			}
			fprintf(out, "\n            ]\n");

			json_obj_end(out, 4, i == top_n - 1);
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

// 用法
static void usage(const char *prog)
{
	fprintf(stderr,
		"用法: %s [选项]\n"
		"\n"
		"锁竞争异常观测工具 —— 基于 eBPF 追踪 futex 等待、识别热点锁，\n"
		"分析线程锁竞争模式并输出结构化诊断报告。\n"
		"\n"
		"选项:\n"
		"  -i, --interval <秒>      采样间隔（默认: %d）\n"
		"  -d, --duration <秒>      总运行时长，0 表示持续运行（默认: 0）\n"
		"  -o, --output <文件路径>  输出到文件（默认: 标准输出）\n"
		"  -p, --profile <Hz>       栈采样频率，需要 root（默认: %d, 0=禁用）\n"
		"  -h, --help               显示本帮助信息\n"
		"\n"
		"报告默认输出到 report/lock.json 和 report/lock.md。\n"
		"\n"
		"示例:\n"
		"  sudo %s                            # 默认参数运行\n"
		"  sudo %s -i 3 -d 60                 # 每 3 秒采样，运行 60 秒\n"
		"  # 配合 stress-ng 复现锁竞争:\n"
		"  # stress-ng --mutex 8 --timeout 180s &\n"
		"  # sudo %s -d 180\n",
		prog, g_cfg.interval, g_cfg.cpu_profile_hz, prog, prog, prog);
}

// run_lock
int run_lock(int argc, char **argv)
{
	int interval         = g_cfg.interval;
	int duration         = 0;
	int profile_hz       = 0; // 锁模块默认不启用 perf 采样，用 futex 点栈
	const char *output_file = NULL;
	static struct option long_opts[] = {
		{"interval", required_argument, 0, 'i'},
		{"duration", required_argument, 0, 'd'},
		{"output",   required_argument, 0, 'o'},
		{"profile",  required_argument, 0, 'p'},
		{"help",     no_argument,       0, 'h'},
		{0, 0, 0, 0}
	};

	int opt;
	while ((opt = getopt_long(argc, argv, "i:d:o:p:h", long_opts, NULL)) != -1) {
		switch (opt) {
		case 'i': interval = atoi(optarg); break;
		case 'd': duration = atoi(optarg); break;
		case 'o': output_file = optarg; break;
		case 'p': profile_hz = atoi(optarg); break;
		case 'h': usage(argv[0]); return 0;
		default:  usage(argv[0]); return 1;
		}
	}

	if (check_interval(interval) != 0)
		return 1;

	FILE *out = open_output(output_file);
	if (!out)
		return 1;

	int ncpu = sysconf(_SC_NPROCESSORS_ONLN);
	if (ncpu < 1) ncpu = 1;

	// 禁用 libbpf 调试输出
	libbpf_set_print(NULL);
	signal(SIGINT, on_signal);
	signal(SIGTERM, on_signal);

	// 加载 CPU skeleton (提供 sched_switch / sched_stat_* / on-CPU 数据)
	struct cpu_anomaly_bpf *cpu_skel = cpu_anomaly_bpf__open_and_load();
	if (!cpu_skel) {
		fprintf(stderr, "无法加载 CPU BPF 程序 (需要 root 权限)\n");
		if (output_file) fclose(out);
		return 1;
	}
	if (cpu_anomaly_bpf__attach(cpu_skel) != 0) {
		fprintf(stderr, "无法挂载 CPU BPF 程序\n");
		cpu_anomaly_bpf__destroy(cpu_skel);
		if (output_file) fclose(out);
		return 1;
	}

	// 加载 Lock skeleton (futex per-key + 等待点栈)
	struct lock_anomaly_bpf *lock_skel = lock_anomaly_bpf__open_and_load();
	if (!lock_skel) {
		fprintf(stderr, "无法加载 Lock BPF 程序\n");
		cpu_anomaly_bpf__destroy(cpu_skel);
		if (output_file) fclose(out);
		return 1;
	}
	if (lock_anomaly_bpf__attach(lock_skel) != 0) {
		fprintf(stderr, "无法挂载 Lock BPF 程序\n");
		lock_anomaly_bpf__destroy(lock_skel);
		cpu_anomaly_bpf__destroy(cpu_skel);
		if (output_file) fclose(out);
		return 1;
	}

	// 可选 perf_event 栈采样 (CPU skeleton 的 on_profile)
	int *pe_fds = NULL;
	int pe_count = 0;
	if (profile_hz > 0) {
		pe_fds = calloc(ncpu, sizeof(int));
		if (pe_fds) {
			struct perf_event_attr attr = {};
			attr.type   = PERF_TYPE_SOFTWARE;
			attr.config = PERF_COUNT_SW_CPU_CLOCK;
			attr.size   = sizeof(attr);
			attr.sample_freq = profile_hz;
			attr.freq   = 1;
			attr.disabled = 1;

			for (int cpu = 0; cpu < ncpu; cpu++) {
				int fd = perf_event_open(&attr, -1, cpu, -1, PERF_FLAG_FD_CLOEXEC);
				if (fd < 0) { pe_fds[cpu] = -1; continue; }
				pe_fds[cpu] = fd;
				bpf_program__attach_perf_event(cpu_skel->progs.on_profile, fd);
				pe_count++;
			}
			if (pe_count > 0) {
				for (int cpu = 0; cpu < ncpu; cpu++)
					if (pe_fds[cpu] >= 0)
						ioctl(pe_fds[cpu], PERF_EVENT_IOC_ENABLE, 0);
				fprintf(stderr, "[*] perf 栈采样已启用, %d Hz, %d/%d CPU\n",
				        profile_hz, pe_count, ncpu);
			}
		}
	}

	int cpu_stats_fd = bpf_map__fd(cpu_skel->maps.pid_stats);
	int lock_stats_fd = bpf_map__fd(lock_skel->maps.lock_pid_stats);
	int futex_key_fd = bpf_map__fd(lock_skel->maps.futex_key_stats);
	int lock_stack_fd = bpf_map__fd(lock_skel->maps.lock_stack_counts);
	int lock_stackmap_fd = bpf_map__fd(lock_skel->maps.lock_stackmap);

	fprintf(stderr, "[*] 锁竞争观测已启动, 采样间隔=%ds\n", interval);
	fprintf(stderr, "[*] 已加载 CPU skeleton (sched_switch/sched_stat_*) + Lock skeleton (futex per-key)\n");

	time_t start = time(NULL);

	while (!exiting) {
		sleep(interval);

		unsigned long long interval_ns = (unsigned long long)interval * 1000000000ULL;

		// 收集锁活动进程
		struct lock_proc_info *procs = NULL;
		int count = 0;
		if (collect_lock_procs(cpu_stats_fd, lock_stats_fd, &procs, &count) != 0) {
			fprintf(stderr, "无法读取进程统计数据\n");
			break;
		}

		// 收集热点锁
		struct hot_lock_entry *hot_locks = NULL;
		int hot_count = 0;
		collect_hot_locks(futex_key_fd, &hot_locks, &hot_count);

		// 收集等待点栈
		struct stack_entry *stacks = NULL;
		int stack_count = 0;
		unsigned long long total_stacks = 0;
		collect_lock_stacks(lock_stack_fd, &stacks, &stack_count, &total_stacks);

		// 输出报告
		print_lock_report(out, procs, count,
		                  hot_locks, hot_count,
		                  stacks, stack_count, total_stacks,
		                  lock_stackmap_fd, ncpu, interval_ns);

		if (exiting || (duration > 0 && time(NULL) - start >= duration)) {
			print_json_report(procs, count, hot_locks, hot_count,
					  stacks, stack_count, total_stacks,
					  lock_stackmap_fd, interval_ns);
			json_to_markdown("report/lock.json", "report/lock.md");
		}

		free(procs);
		free(hot_locks);
		free(stacks);

		if (exiting || (duration > 0 && time(NULL) - start >= duration))
			break;

		// 重置 map
		reset_map(lock_stats_fd);
		reset_map(futex_key_fd);
		reset_map(lock_stack_fd);
		reset_map(cpu_stats_fd);
	}

	if (pe_fds) {
		for (int cpu = 0; cpu < ncpu; cpu++)
			if (pe_fds[cpu] >= 0) {
				ioctl(pe_fds[cpu], PERF_EVENT_IOC_DISABLE, 0);
				close(pe_fds[cpu]);
			}
		free(pe_fds);
	}

	fprintf(stderr, "[*] 正在退出...\n");
	lock_anomaly_bpf__destroy(lock_skel);
	cpu_anomaly_bpf__destroy(cpu_skel);
	if (output_file) fclose(out);

	return 0;
}
