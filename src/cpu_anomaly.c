// cpu_anomaly.c — CPU 异常观测与根因定位 (用户态)
//
// 加载 BPF skeleton, 周期性读取 map 统计, 检测异常并输出诊断报告.
//
// 用法:
//   cpu_anomaly [-i interval_s] [-d duration_s] [-o output_file] [--cpu-threshold 90]
//               [-p profile_hz]

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
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
#include "cpu_anomaly.skel.h"
#include "../include/report_json.h"
#include "../include/report_md.h"
#include "../include/cpu_anomaly.h"
#include "../include/common.h"

// 配置常量
#define DEFAULT_CPU_THRESHOLD 90.0    // CPU% 异常阈值
#define CSWITCH_WARN_PER_MIN  30000   // cswitch/min 警告阈值
#define CSWITCH_CRIT_PER_MIN  50000   // cswitch/min 严重阈值
#define SCHED_DELAY_WARN_US   5000    // avg 调度延迟 警告阈值 (us)
#define SCHED_DELAY_CRIT_US   20000   // avg 调度延迟 严重阈值 (us)
#define BUSYLOOP_CS_PER_MIN   5000    // busy loop 判定: 切换 < 5000/min
#define STACK_CONC_RATIO      0.8     // 栈集中度: top1 占比 > 80% = 集中

// ─── 统计结构 (必须与 BPF 侧一致) ────────────────────────────────
// 后续改为统一在 common.h 里定义
struct pid_stats {
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

// ─── 进程信息 ────────────────────────────────────────────────────
struct proc_info {
	__u32 pid;
	char comm[16];
	struct pid_stats stats;
};

// ─── 栈聚合 ──────────────────────────────────────────────────────
struct stack_entry {
	__s32 stack_id;
	__u64 count;
};

#include "../include/utils.h"

// ─── libbpf 日志 ─────────────────────────────────────────────────
static int print_fn(enum libbpf_print_level lvl, const char *fmt, va_list ap)
{
	if (lvl == LIBBPF_DEBUG) return 0;
	return vfprintf(stderr, fmt, ap);
}

// ─── 收集 map 中所有进程统计 ─────────────────────────────────────
static int collect_procs(int map_fd, struct proc_info **out, int *out_count)
{
	int capacity = 256;
	int count    = 0;
	*out = malloc(capacity * sizeof(struct proc_info));
	if (!*out) return -1;

	__u32 key = 0, next_key;
	while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0) {
		struct pid_stats val = {};
		if (bpf_map_lookup_elem(map_fd, &next_key, &val) != 0) {
			key = next_key;
			continue;
		}

		if (val.on_cpu_ns == 0 && val.cswitch_total == 0 &&
		    val.wakeup_count == 0 && val.wait_ns == 0 &&
		    val.cpu_runtime_ns == 0) {
			key = next_key;
			continue;
		}

		if (count >= capacity) {
			capacity *= 2;
			*out = realloc(*out, capacity * sizeof(struct proc_info));
			if (!*out) return -1;
		}

		struct proc_info *p = &(*out)[count];
		p->pid   = next_key;
		p->stats = val;
		read_comm(next_key, p->comm, sizeof(p->comm));
		count++;
		key = next_key;
	}

	*out_count = count;
	return 0;
}

// ─── CPU% 比较 (降序) ────────────────────────────────────────────
static int cmp_cpu(const void *a, const void *b)
{
	const struct proc_info *pa = a, *pb = b;
	double ca = (double)pa->stats.on_cpu_ns;
	double cb = (double)pb->stats.on_cpu_ns;
	return (cb > ca) - (ca > cb);
}

// ─── stack 比较 (降序) ──────────────────────────────────────────
static int cmp_stack(const void *a, const void *b)
{
	const struct stack_entry *sa = a, *sb = b;
	return (sb->count > sa->count) - (sa->count > sb->count);
}

// ─── 收集栈采样统计 ──────────────────────────────────────────────
static int collect_stacks(int counts_fd, struct stack_entry **out, int *out_count,
                          __u64 *total_samples)
{
	int capacity = 256;
	int count = 0;
	*out = malloc(capacity * sizeof(struct stack_entry));
	if (!*out) return -1;

	__u32 key = 0, next_key;
	*total_samples = 0;

	while (bpf_map_get_next_key(counts_fd, &key, &next_key) == 0) {
		__u64 val = 0;
		if (bpf_map_lookup_elem(counts_fd, &next_key, &val) != 0) {
			key = next_key;
			continue;
		}
		*total_samples += val;

		if (count >= capacity) {
			capacity *= 2;
			*out = realloc(*out, capacity * sizeof(struct stack_entry));
			if (!*out) return -1;
		}

		(*out)[count].stack_id = (__s32)next_key;
		(*out)[count].count    = val;
		count++;
		key = next_key;
	}

	*out_count = count;
	return 0;
}

// 调度器检测
static void check_scheduler_info(struct cpu_anomaly_bpf *skel,
                                 char *sched_name, size_t name_len,
                                 char *preempt_model, size_t pm_len,
                                 int *schedstats_on)
{
  // 读取内核版本 -> EEVDF or CFS
  struct utsname uts;
  uname(&uts);
  int major, minor;
  sscanf(uts.release, "%d.%d", &major, &minor);

  if (major > 6 || (major == 6 && minor >= 6))
    snprintf(sched_name, name_len, "EEVDF (fair_sched_class)");
  else
    snprintf(sched_name, name_len, "CFS (fair_sched_class)");

  // 抢占模型, 从/proc/version 读取
  *preempt_model = '\0';
  FILE *f = fopen("/proc/version", "r");
  if (f)
  {
    char line[256];
    if (fgets(line, sizeof(line), f))
    {
      if (strstr(line, "PREEMPT_DYNAMIC"))
        snprintf(preempt_model, pm_len, "PREEMPT_DYNAMIC");
      else if (strstr(line, "PREEMPT_RT"))
        snprintf(preempt_model, pm_len, "PREEMPT_RT");
      else if (strstr(line, "PREEMPT"))
        snprintf(preempt_model, pm_len, "PREEMPT (voluntary)");
    }
    fclose(f);
  }

  // 查看schedstats是否启用
  *schedstats_on = 0;
  f = fopen("/proc/sys/kernel/sched_schedstats", "r");
  if (f)
  {
    char c = '0';
    fread(&c, 1, 1, f);
    if (c == '1')
      *schedstats_on = 1;
    fclose(f);
  }

  // 读取BPF map 确定fair_sched_class 被调用
  __u32 zero = 0;
  __u64 fair_count = 0;
  bpf_map_lookup_elem(bpf_map__fd(skel->maps.sched_class_check), &zero, &fair_count);
}

// 输出一条调用栈链路
static void print_call_stack(FILE *out, int stackmap_fd, __s32 stack_id,
			     pid_t resolve_pid, const char *prefix)
{
	__u64 ips[127];
	memset(ips, 0, sizeof(ips));

	if (bpf_map_lookup_elem(stackmap_fd, &stack_id, ips) != 0) {
		fprintf(out, "%s  (无法读取栈数据)\n", prefix);
		return;
	}

	int depth = 0;
	for (int i = 0; i < 127 && ips[i] != 0; i++)
		depth++;

	if (depth == 0) {
		fprintf(out, "%s  (无用户态栈 — 可能为内核线程)\n", prefix);
		return;
	}

	for (int i = 0; i < depth; i++) {
		char sym[256];
		resolve_ip(resolve_pid, ips[i], sym, sizeof(sym));
		fprintf(out, "%s  #%-2d  %s\n", prefix, i, sym);
	}
}

// 打印单个时间窗口的文本诊断报告 
static void print_report(FILE *out,
                         struct proc_info *procs,
                         int count,
                         __u64 total_interval_ns,
                         int ncpu,
                         double cpu_threshold,
                         struct stack_entry *stacks,
                         int stack_count,
                         __u64 total_stack_samples,
                         int stackmap_fd,
                         const char *sched_name,
                         const char *preempt_model,
                         int schedstats_on)
{
	char ts[32];
	iso_timestamp(ts, sizeof(ts));
	double duration_s = (double)total_interval_ns / 1e9;

	// 读取系统指标
	struct sys_metrics sys;
	read_sys_metrics(&sys);

	// ═══════════════════════════════════════════════════════════
	//  报告头部
	// ═══════════════════════════════════════════════════════════
	fprintf(out,
	        "======================================================================\n"
	        "  CPU 异常观测诊断报告\n"
	        "======================================================================\n"
	        "  异常时间窗口: %s  (采样间隔 %.1fs)\n"
	        "----------------------------------------------------------------------\n"
	        "  系统概览\n"
	        "  CPU 核心数: %-4d   活跃进程数: %d\n"
	        "  系统负载:       1min %.2f   5min %.2f   15min %.2f\n"
	        "  RunQ 深度信息:    正在运行or可运行的进程数: %d  被阻塞的进程数: %d\n"
	        "  调度器: %-24s  抢占模型: %s\n"
	        "  schedstats: %-12s  CPU 计时: %s\n"
	        "======================================================================\n\n",
	        ts, duration_s, ncpu, count,
	        sys.load1, sys.load5, sys.load15,
	        sys.procs_running, sys.procs_blocked,
	        sched_name, preempt_model,
	        schedstats_on ? "启用" : "未启用",
	        schedstats_on ? "sched_stat_runtime (精确)" : "sched_switch (挂墙)");

	// 按 CPU% 排序
	qsort(procs, count, sizeof(struct proc_info), cmp_cpu);

	// ── 栈采样概要 ──
	if (total_stack_samples > 0) {
		qsort(stacks, stack_count, sizeof(struct stack_entry), cmp_stack);
		fprintf(out,
		        "──────────────────────────────────────────────────────────────────────\n"
		        "  栈采样概要 (总采样: %llu)\n"
		        "──────────────────────────────────────────────────────────────────────\n",
		        total_stack_samples);
		int top_n = stack_count < 5 ? stack_count : 5;
		pid_t resolve_pid = (count > 0) ? procs[0].pid : getpid();
		for (int i = 0; i < top_n; i++) {
			fprintf(out, "  stack #%d: id=%d  采样 %llu 次 (%.1f%%)\n",
			        i + 1, stacks[i].stack_id, stacks[i].count,
			        (double)stacks[i].count / (double)total_stack_samples * 100.0);
			if (stackmap_fd >= 0)
				print_call_stack(out, stackmap_fd, stacks[i].stack_id,
				                 resolve_pid, "    ");
			fprintf(out, "\n");
		}
	}

	int seq = 0;
	for (int i = 0; i < count && i < 20; i++) {
		struct pid_stats *s = &procs[i].stats;

		// CPU 时间: schedstats 开启时优先用内核核算值，否则 fallback 到挂墙时间
		__u64 cpu_ns = (schedstats_on && s->cpu_runtime_ns > 0)
				? s->cpu_runtime_ns : s->on_cpu_ns;
		double cpu_pct  = (double)cpu_ns / (double)total_interval_ns * 100.0;
		double cswitch_pm = (s->cswitch_total > 0)
			? (double)s->cswitch_total / ((double)total_interval_ns / 60e9)
			: 0;
		double invol_pm = (s->cswitch_involuntary > 0)
			? (double)s->cswitch_involuntary / ((double)total_interval_ns / 60e9)
			: 0;
		double vol_pm = (s->cswitch_voluntary > 0)
			? (double)s->cswitch_voluntary / ((double)total_interval_ns / 60e9)
			: 0;

		// 调度延迟: 优先用 sched_stat_wait 数据, fallback 到手动计算
		double avg_delay_us;
		if (s->wait_ns > 0 && s->wakeup_count > 0) {
			avg_delay_us = (double)s->wait_ns / (double)s->wakeup_count / 1000.0;
		} else if (s->wakeup_count > 0) {
			avg_delay_us = (double)s->total_sched_delay_ns /
				       (double)s->wakeup_count / 1000.0;
		} else {
			avg_delay_us = 0;
		}
		double max_delay_us = (double)s->max_sched_delay_ns / 1000.0;

		double vol_ratio = (s->cswitch_total > 0)
			? (double)s->cswitch_voluntary / (double)s->cswitch_total
			: 0;

		double futex_avg_us = (s->futex_wait_count > 0)
			? (double)s->futex_wait_ns / (double)s->futex_wait_count / 1000.0
			: 0;

		// ── 判定异常 & 根因分类 ──
		int is_anomaly = 0;
		const char *subtype = NULL;
		const char *root_cause = NULL;
		const char *suggestion = NULL;
		char evidence[6][256];
		int ev_count = 0;

		// 判定栈集中度
		double stack_concentration = 0;
		if (total_stack_samples > 0) {
			stack_concentration = (double)stacks[0].count /
			                      (double)total_stack_samples;
		}

		// ── 分支1: CPU 高占用 ──
		if (cpu_pct > cpu_threshold) {
			is_anomaly = 1;
			snprintf(evidence[ev_count++], sizeof(evidence[0]),
			         "CPU 占用 %.1f%% 超过阈值 %.0f%%", cpu_pct, cpu_threshold);

			snprintf(evidence[ev_count++], sizeof(evidence[0]),
		         "系统负载(1min 内平均) %.2f, RunQ 深度 %d, 阻塞 %d",
		         sys.load1, sys.procs_running, sys.procs_blocked);

			// 1a: 切换极少 + 栈高度集中 → busy loop
			if (cswitch_pm < BUSYLOOP_CS_PER_MIN &&
			    stack_concentration > STACK_CONC_RATIO) {
				subtype = "CPU异常占用 (busy loop)";
				root_cause = "进程陷入单点 busy loop，切换极少且栈高度集中在一处";
				suggestion = "perf top 定位到具体函数后检查循环退出条件；"
				             "考虑添加 usleep/yield";
			}
			// 1b: 切换极少但无栈数据 → "疑似 busy loop"
			else if (cswitch_pm < BUSYLOOP_CS_PER_MIN &&
			         total_stack_samples == 0) {
				subtype = "CPU异常占用 (疑为 busy loop)";
				root_cause = "进程切换频率极低 (< 5000/min)，疑似 busy loop；"
				             "建议启用栈采样确认";
				suggestion = "使用 --profile 启用栈采样定位热点函数；"
				             "或使用 perf top 观察";
			}
			// 1c: 被动切换占主导 → CPU 密集计算
			else if (s->cswitch_involuntary > s->cswitch_voluntary * 10) {
				subtype = "CPU异常占用 (CPU 密集计算)";
				root_cause = "用户态 CPU 密集型计算致 CPU 饱和，"
				             "进程长期占核被反复抢占";
				suggestion = "使用 perf top/flamegraph 分析热点函数；"
				             "考虑 cgroup CPU limit 隔离";
				snprintf(evidence[ev_count++], sizeof(evidence[0]),
				         "被动切换 %.0f/min 占绝对主导 (主动 %.0f/min)，证实 CPU 争抢",
				         invol_pm, vol_pm);
				if (sys.load1 > ncpu * 1.5)
					snprintf(evidence[ev_count++], sizeof(evidence[0]),
					         "系统负载 %.2f 远超 CPU 核心数 %d，全局 CPU 饱和",
					         sys.load1, ncpu);
			}
			// 1d: 其他高 CPU
			else {
				subtype = "CPU异常占用";
				root_cause = "进程持续高 CPU 占用，疑似计算热点或 busy loop";
				suggestion = "使用 perf top/flamegraph 分析热点函数；"
				             "考虑 cgroup CPU limit 隔离";
			}
		}

		// ── 分支2: 线程竞争 / 锁竞争 ──
		if (!is_anomaly && vol_ratio > VOLUNTARY_RATIO_HIGH &&
		    cswitch_pm > CSWITCH_WARN_PER_MIN) {
			is_anomaly = 1;
			subtype = "线程/锁竞争";
			snprintf(evidence[ev_count++], sizeof(evidence[0]),
			         "RunQ 深度瞬时 %d, 负载 %.2f — CPU 未饱和但切换频繁",
			         sys.procs_running, sys.load1);
			if (s->futex_wait_count > 0) {
				root_cause = "自愿切换占比高 + futex 等待显著，"
				             "多线程锁竞争或同步等待";
				suggestion = "使用 perf lock 分析锁热点；排查 futex 等待模式";
				snprintf(evidence[ev_count++], sizeof(evidence[0]),
				         "自愿切换占比 %.0f%% (%.0f/min)，futex 等待 %llu 次/avg %.0fus",
				         vol_ratio * 100, vol_pm,
				         s->futex_wait_count, futex_avg_us);
			} else {
				root_cause = "自愿切换占比高，疑似锁等待或 I/O 阻塞";
				suggestion = "使用 off-CPU 火焰图分析阻塞原因；"
				             "考虑 strace 观察系统调用模式";
				snprintf(evidence[ev_count++], sizeof(evidence[0]),
				         "自愿切换占比 %.0f%% (%.0f/min)，总切换 %.0f/min",
				         vol_ratio * 100, vol_pm, cswitch_pm);
			}
			snprintf(evidence[ev_count++], sizeof(evidence[0]),
			         "CPU 占用仅 %.1f%%，排除纯计算热点，指向等待/阻塞模式",
			         cpu_pct);
		}

		// ── 分支3: 调度延迟异常 ──
		if (avg_delay_us > SCHED_DELAY_CRIT_US) {
			if (!is_anomaly) {
				is_anomaly = 1;
				subtype = "调度延迟异常";
			}
			if (!root_cause)
				root_cause = "调度延迟显著偏高，CPU 资源竞争或 run queue 拥堵";
			if (!suggestion)
				suggestion = "检查 run queue 深度和 CPU 负载；"
				             "考虑增加 CPU 资源或调整进程优先级";
			snprintf(evidence[ev_count++], sizeof(evidence[0]),
			         "平均调度延迟 %.0fus 超过严重阈值 %dus",
			         avg_delay_us, SCHED_DELAY_CRIT_US);
		} else if (avg_delay_us > SCHED_DELAY_WARN_US) {
			if (!is_anomaly) {
				is_anomaly = 1;
				subtype = "调度延迟偏高";
				root_cause = "CPU 负载较高致调度延迟升高";
				suggestion = "监控 run queue 深度变化趋势";
			}
			snprintf(evidence[ev_count++], sizeof(evidence[0]),
			         "平均调度延迟 %.0fus 超过警告阈值 %dus",
			         avg_delay_us, SCHED_DELAY_WARN_US);
		}

		// ── 分支4: 上下文切换风暴 ──
		if (cswitch_pm > CSWITCH_CRIT_PER_MIN && !is_anomaly) {
			is_anomaly = 1;
			subtype = "上下文切换风暴";
			root_cause = "上下文切换频率极高，多线程争用或过度 I/O 唤醒";
			suggestion = "检查线程池大小；排查不必要的 wakeup；"
			             "使用 off-CPU 分析定位阻塞源";
			snprintf(evidence[ev_count++], sizeof(evidence[0]),
			         "上下文切换 %.0f/min 达风暴级别 (>%d/min)",
			         cswitch_pm, CSWITCH_CRIT_PER_MIN);
		}

		// ── 分支5: 核间迁移异常 ──
		if (s->migrate_count > (__u64)cswitch_pm / 2 && s->migrate_count > 100) {
			if (!is_anomaly) {
				is_anomaly = 1;
				if (!subtype) subtype = "核间迁移异常";
			}
			snprintf(evidence[ev_count++], sizeof(evidence[0]),
			         "核间迁移 %llu 次，占比过高 (>50%% 切换)，放大调度开销",
			         s->migrate_count);
			if (!suggestion) {
				suggestion = "检查 CPU affinity 设置；"
				             "考虑 taskset/cpuset 绑定关键进程";
			}
		}

		// 按 CPU%>50% 或异常才输出详情
		if (cpu_pct < 50.0 && !is_anomaly) continue;

		seq++;

		// ── 进程标题行 ──
		const char *status_icon = is_anomaly ? "!!" : "OK";
		fprintf(out,
		        "──────────────────────────────────────────────────────────────────────\n"
		        "  [%d] PID %-6u  %-16s  状态: %s",
		        seq, procs[i].pid, procs[i].comm, status_icon);
		if (is_anomaly && subtype)
			fprintf(out, "  %s", subtype);
		fprintf(out, "\n"
		        "──────────────────────────────────────────────────────────────────────\n\n");

		// ── 关键指标 ──
		fprintf(out,
		        "  关键指标:\n"
		        "    CPU 占用:           %6.1f%%\n"
		        "    上下文切换:         %6.0f/min  (主动: %llu,  被动: %llu)\n"
		        "    主动切换占比:       %6.0f%%\n"
		        "    调度延迟 (avg):     %6.1f us\n"
		        "    调度延迟 (max):     %6.1f us\n"
		        "    唤醒次数:           %llu\n",
		        cpu_pct, cswitch_pm,
		        s->cswitch_voluntary, s->cswitch_involuntary,
		        vol_ratio * 100.0,
		        avg_delay_us, max_delay_us,
		        s->wakeup_count);

		// sched_stat 数据
		if (s->wait_ns > 0 || s->sleep_ns > 0 || s->blocked_ns > 0)
			fprintf(out,
			        "    等待(runq):         %6.1f ms\n"
			        "    睡眠:               %6.1f ms\n"
			        "    阻塞(I/O等):        %6.1f ms\n",
			        (double)s->wait_ns / 1e6,
			        (double)s->sleep_ns / 1e6,
			        (double)s->blocked_ns / 1e6);

		// 迁移 & futex
		fprintf(out,
		        "    核间迁移:           %llu 次\n",
		        s->migrate_count);
		if (s->futex_wait_count > 0)
			fprintf(out,
			        "    futex 等待:         %llu 次, avg %.0f us\n",
			        s->futex_wait_count,
			        futex_avg_us);

		fprintf(out, "\n");

		// ── 诊断信息 (仅异常进程) ──
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
		fprintf(out, "  (无高 CPU 占用或异常进程)\n\n");

	fprintf(out, "======================================================================\n\n");
	fflush(out);
}

// ─── JSON 报告输出 (使用统一 report_json 构建器) ─────────────────
static void print_json_report(struct proc_info *procs, int count,
			      __u64 total_interval_ns, int ncpu,
			      double cpu_threshold,
			      struct stack_entry *stacks, int stack_count,
			      __u64 total_stack_samples,
			      int schedstats_on,
			      const char *sched_name, const char *preempt_model,
			      int stackmap_fd)
{
	const char *path = "report/cpu.json";
	FILE *out = json_open(path);
	if (!out) return;

	char ts[32];
	iso_timestamp(ts, sizeof(ts));
	double duration_s = (double)total_interval_ns / 1e9;

	struct sys_metrics sys;
	read_sys_metrics(&sys);

	qsort(procs, count, sizeof(struct proc_info), cmp_cpu);

	double stack_concentration = 0;
	if (total_stack_samples > 0 && stack_count > 0) {
		qsort(stacks, stack_count, sizeof(struct stack_entry), cmp_stack);
		stack_concentration = (double)stacks[0].count /
				      (double)total_stack_samples;
	}

	// 顶层对象
	fprintf(out, "{\n");
	json_kv_str(out, 1, "module", "cpu", 0);
	json_kv_str(out, 1, "timestamp", ts, 0);
	json_kv_double(out, 1, "duration_s", duration_s, "%.1f", 0);

	// system
	char buf[256];
	json_obj_begin(out, 1, "system");
	snprintf(buf, sizeof(buf), "%d", ncpu);
	json_kv_str(out, 2, "CPU 核心数", buf, 0);
	snprintf(buf, sizeof(buf), "%d", count);
	json_kv_str(out, 2, "活跃进程数", buf, 0);
	json_kv_str(out, 2, "调度器", sched_name, 0);
	json_kv_str(out, 2, "抢占模型", preempt_model, 0);
	json_kv_str(out, 2, "schedstats",
		    schedstats_on ? "启用 (精确核算)" : "未启用 (挂墙时间)", 0);
	snprintf(buf, sizeof(buf), "%.2f / %.2f / %.2f",
		 sys.load1, sys.load5, sys.load15);
	json_kv_str(out, 2, "系统负载 (1m/5m/15m)", buf, 0);
	snprintf(buf, sizeof(buf), "%d", sys.procs_running);
	json_kv_str(out, 2, "RunQ 深度 (瞬时)", buf, 0);
	snprintf(buf, sizeof(buf), "%d", sys.procs_blocked);
	json_kv_str(out, 2, "不可中断阻塞", buf, 0);
	snprintf(buf, sizeof(buf), "%.0f%%", cpu_threshold);
	json_kv_str(out, 2, "CPU 异常阈值", buf, 1);
	json_obj_end(out, 1, 0);

	// sections 数组
	json_arr_begin(out, 1, "sections");

	// section 1: stacks (if available)
	if (total_stack_samples > 0 && stack_count > 0) {
		json_obj_begin_nokey(out, 2);
		json_kv_str(out, 3, "type", "stacks", 0);
		json_kv_str(out, 3, "title", "栈采样概要", 0);
		json_kv_uint(out, 3, "total_samples", total_stack_samples, 0);
		json_arr_begin(out, 3, "top_stacks");
		int top_n = stack_count < 5 ? stack_count : 5;
		pid_t resolve_pid = (count > 0) ? procs[0].pid : getpid();
		for (int i = 0; i < top_n; i++) {
			json_obj_begin_nokey(out, 4);
			json_kv_int(out, 5, "rank", i + 1, 0);
			json_kv_uint(out, 5, "count", stacks[i].count, 0);
			json_kv_double(out, 5, "pct",
				(double)stacks[i].count / (double)total_stack_samples * 100.0,
				"%.1f", 0);

			// 解析调用栈帧
			__u64 ips[127];
			memset(ips, 0, sizeof(ips));
			int depth = 0;
			if (stackmap_fd >= 0 &&
			    bpf_map_lookup_elem(stackmap_fd, &stacks[i].stack_id, ips) == 0) {
				for (int j = 0; j < 127 && ips[j] != 0; j++)
					depth++;
			}

			json_arr_begin(out, 5, "frames");
			for (int j = 0; j < depth; j++) {
				char sym[256];
				resolve_ip(resolve_pid, ips[j], sym, sizeof(sym));
				json_indent(out, 6);
				fprintf(out, "\"%s\"%s\n", sym, j < depth - 1 ? "," : "");
			}
			json_arr_end(out, 5, 1);
			json_obj_end(out, 4, i == top_n - 1);
		}
		json_arr_end(out, 3, 1);
		json_obj_end(out, 2, 0);
	}

	// section 2: TOP 进程指标 table
	{
		json_obj_begin_nokey(out, 2);
		json_kv_str(out, 3, "type", "table", 0);
		json_kv_str(out, 3, "title", "TOP 进程指标", 0);

		// columns
		const char *cols[] = {
			"PID", "进程名", "CPU%", "切换/min", "主动", "被动",
			"调度延迟(avg)", "调度延迟(max)", "迁移", "futex", "状态"
		};
		json_arr_begin(out, 3, "columns");
		for (int i = 0; i < 11; i++)
			fprintf(out, "%s\"%s\"%s", i == 0 ? "          " : "",
				cols[i], i < 10 ? ",\n" : "\n");
		json_indent(out, 3);
		fprintf(out, "],\n"); // manual close for inline

		// rows
		json_arr_begin(out, 3, "rows");
		int limit = count < 20 ? count : 20;
		for (int i = 0; i < limit; i++) {
			struct pid_stats *s = &procs[i].stats;
			__u64 cpu_ns = (schedstats_on && s->cpu_runtime_ns > 0)
				? s->cpu_runtime_ns : s->on_cpu_ns;
			double cpu_pct = (double)cpu_ns / (double)total_interval_ns * 100.0;
			double cswitch_pm = (s->cswitch_total > 0)
				? (double)s->cswitch_total / ((double)total_interval_ns / 60e9) : 0;
			double avg_delay_us;
			if (s->wait_ns > 0 && s->wakeup_count > 0)
				avg_delay_us = (double)s->wait_ns / (double)s->wakeup_count / 1000.0;
			else if (s->wakeup_count > 0)
				avg_delay_us = (double)s->total_sched_delay_ns /
					       (double)s->wakeup_count / 1000.0;
			else
				avg_delay_us = 0;
			double max_delay_us = (double)s->max_sched_delay_ns / 1000.0;
			double vol_ratio = (s->cswitch_total > 0)
				? (double)s->cswitch_voluntary / (double)s->cswitch_total : 0;

			const char *status;
			if (cpu_pct > cpu_threshold) {
				if (cswitch_pm < BUSYLOOP_CS_PER_MIN &&
				    stack_concentration > STACK_CONC_RATIO)
					status = "!! busy loop";
				else if (s->cswitch_involuntary > s->cswitch_voluntary * 10)
					status = "!! CPU密集";
				else
					status = "!! 高CPU";
			} else if (vol_ratio > VOLUNTARY_RATIO_HIGH &&
				   cswitch_pm > CSWITCH_WARN_PER_MIN)
				status = "!! 锁竞争";
			else if (avg_delay_us > SCHED_DELAY_CRIT_US)
				status = "!! 调度延迟";
			else
				status = "OK";

			json_indent(out, 4);
			fprintf(out, "[\"%u\", \"%s\", \"%.1f\", \"%.0f\", \"%llu\", \"%llu\", "
				"\"%.0fus\", \"%.0fus\", \"%llu\", \"%llu\", \"%s\"]%s\n",
				procs[i].pid, procs[i].comm, cpu_pct, cswitch_pm,
				s->cswitch_voluntary, s->cswitch_involuntary,
				avg_delay_us, max_delay_us,
				s->migrate_count, s->futex_wait_count,
				status,
				i < limit - 1 ? "," : "");
		}
		json_arr_end(out, 3, 1);
		json_obj_end(out, 2, 0);
	}

	// section 3: diagnosis
	{
		json_obj_begin_nokey(out, 2);
		json_kv_str(out, 3, "type", "diagnosis", 0);
		json_kv_str(out, 3, "title", "异常进程诊断分析", 0);
		json_arr_begin(out, 3, "findings");

		int diag_count = 0;
		int limit2 = count < 20 ? count : 20;
		for (int i = 0; i < limit2; i++) {
			struct pid_stats *s = &procs[i].stats;
			__u64 cpu_ns = (schedstats_on && s->cpu_runtime_ns > 0)
				? s->cpu_runtime_ns : s->on_cpu_ns;
			double cpu_pct = (double)cpu_ns / (double)total_interval_ns * 100.0;
			double cswitch_pm = (s->cswitch_total > 0)
				? (double)s->cswitch_total / ((double)total_interval_ns / 60e9) : 0;
			double vol_ratio = (s->cswitch_total > 0)
				? (double)s->cswitch_voluntary / (double)s->cswitch_total : 0;
			double invol_pm = (s->cswitch_involuntary > 0)
				? (double)s->cswitch_involuntary / ((double)total_interval_ns / 60e9) : 0;
			double vol_pm = (s->cswitch_voluntary > 0)
				? (double)s->cswitch_voluntary / ((double)total_interval_ns / 60e9) : 0;
			double avg_delay_us;
			if (s->wait_ns > 0 && s->wakeup_count > 0)
				avg_delay_us = (double)s->wait_ns / (double)s->wakeup_count / 1000.0;
			else if (s->wakeup_count > 0)
				avg_delay_us = (double)s->total_sched_delay_ns /
					       (double)s->wakeup_count / 1000.0;
			else
				avg_delay_us = 0;
			double max_delay_us = (double)s->max_sched_delay_ns / 1000.0;
			double futex_avg_us = (s->futex_wait_count > 0)
				? (double)s->futex_wait_ns / (double)s->futex_wait_count / 1000.0 : 0;

			int is_anomaly = 0;
			const char *subtype = NULL;
			const char *root_cause = NULL;
			const char *suggestion = NULL;
			char evidence[8][256];
			int ev_count = 0;

			if (cpu_pct > cpu_threshold) {
				is_anomaly = 1;
				snprintf(evidence[ev_count++], sizeof(evidence[0]),
				         "CPU 占用 %.1f%% 超过阈值 %.0f%%", cpu_pct, cpu_threshold);
				snprintf(evidence[ev_count++], sizeof(evidence[0]),
				         "系统负载 %.2f, RunQ 深度 %d, 阻塞 %d",
				         sys.load1, sys.procs_running, sys.procs_blocked);

				if (cswitch_pm < BUSYLOOP_CS_PER_MIN &&
				    stack_concentration > STACK_CONC_RATIO) {
					subtype = "CPU异常占用 (busy loop)";
					root_cause = "进程陷入单点 busy loop，切换极少且栈高度集中在一处";
					suggestion = "perf top 定位到具体函数后检查循环退出条件；考虑添加 usleep/yield";
				} else if (cswitch_pm < BUSYLOOP_CS_PER_MIN &&
				           total_stack_samples == 0) {
					subtype = "CPU异常占用 (疑为 busy loop)";
					root_cause = "进程切换频率极低，疑似 busy loop；建议启用栈采样确认";
					suggestion = "使用 --profile 启用栈采样定位热点函数；或使用 perf top 观察";
				} else if (s->cswitch_involuntary > s->cswitch_voluntary * 10) {
					subtype = "CPU异常占用 (CPU 密集计算)";
					root_cause = "用户态 CPU 密集型计算致 CPU 饱和，进程长期占核被反复抢占";
					suggestion = "使用 perf top/flamegraph 分析热点函数；考虑 cgroup CPU limit 隔离";
					snprintf(evidence[ev_count++], sizeof(evidence[0]),
					         "被动切换 %.0f/min 占主导 (主动 %.0f/min)，证实 CPU 争抢",
					         invol_pm, vol_pm);
					if (sys.load1 > ncpu * 1.5)
						snprintf(evidence[ev_count++], sizeof(evidence[0]),
						         "系统负载 %.2f 远超 CPU 核心数 %d，全局 CPU 饱和",
						         sys.load1, ncpu);
				} else {
					subtype = "CPU异常占用";
					root_cause = "进程持续高 CPU 占用，疑似计算热点或 busy loop";
					suggestion = "使用 perf top/flamegraph 分析热点函数；考虑 cgroup CPU limit 隔离";
				}
			}

			if (!is_anomaly && vol_ratio > VOLUNTARY_RATIO_HIGH &&
			    cswitch_pm > CSWITCH_WARN_PER_MIN) {
				is_anomaly = 1;
				subtype = "线程/锁竞争";
				snprintf(evidence[ev_count++], sizeof(evidence[0]),
				         "RunQ 瞬时 %d, 负载 %.2f — CPU 未饱和但切换频繁",
				         sys.procs_running, sys.load1);
				if (s->futex_wait_count > 0) {
					root_cause = "自愿切换占比高 + futex 等待显著，多线程锁竞争或同步等待";
					suggestion = "使用 perf lock 分析锁热点；排查 futex 等待模式";
					snprintf(evidence[ev_count++], sizeof(evidence[0]),
					         "自愿切换占比 %.0f%% (%.0f/min)，futex 等待 %llu 次/avg %.0fus",
					         vol_ratio * 100, vol_pm,
					         s->futex_wait_count, futex_avg_us);
				} else {
					root_cause = "自愿切换占比高，疑似锁等待或 I/O 阻塞";
					suggestion = "使用 off-CPU 火焰图分析阻塞原因；考虑 strace 观察系统调用模式";
					snprintf(evidence[ev_count++], sizeof(evidence[0]),
					         "自愿切换占比 %.0f%% (%.0f/min)，总切换 %.0f/min",
					         vol_ratio * 100, vol_pm, cswitch_pm);
				}
				snprintf(evidence[ev_count++], sizeof(evidence[0]),
				         "CPU 占用仅 %.1f%%，排除纯计算热点，指向等待/阻塞模式", cpu_pct);
			}

			if (avg_delay_us > SCHED_DELAY_CRIT_US) {
				if (!is_anomaly) {
					is_anomaly = 1;
					subtype = "调度延迟异常";
				}
				if (!root_cause)
					root_cause = "调度延迟显著偏高，CPU 资源竞争或 run queue 拥堵";
				if (!suggestion)
					suggestion = "检查 run queue 深度和 CPU 负载；考虑增加 CPU 资源或调整进程优先级";
				snprintf(evidence[ev_count++], sizeof(evidence[0]),
				         "平均调度延迟 %.0fus 超过严重阈值 %dus",
				         avg_delay_us, SCHED_DELAY_CRIT_US);
			} else if (avg_delay_us > SCHED_DELAY_WARN_US) {
				if (!is_anomaly) {
					is_anomaly = 1;
					subtype = "调度延迟偏高";
					root_cause = "CPU 负载较高致调度延迟升高";
					suggestion = "监控 run queue 深度变化趋势";
				}
				snprintf(evidence[ev_count++], sizeof(evidence[0]),
				         "平均调度延迟 %.0fus 超过警告阈值 %dus",
				         avg_delay_us, SCHED_DELAY_WARN_US);
			}

			if (cswitch_pm > CSWITCH_CRIT_PER_MIN && !is_anomaly) {
				is_anomaly = 1;
				subtype = "上下文切换风暴";
				root_cause = "上下文切换频率极高，多线程争用或过度 I/O 唤醒";
				suggestion = "检查线程池大小；排查不必要的 wakeup；使用 off-CPU 分析定位阻塞源";
				snprintf(evidence[ev_count++], sizeof(evidence[0]),
				         "上下文切换 %.0f/min 达风暴级别 (>%d/min)",
				         cswitch_pm, CSWITCH_CRIT_PER_MIN);
			}

			if (s->migrate_count > (unsigned long long)cswitch_pm / 2 &&
			    s->migrate_count > 100) {
				if (!is_anomaly) {
					is_anomaly = 1;
					if (!subtype) subtype = "核间迁移异常";
				}
				snprintf(evidence[ev_count++], sizeof(evidence[0]),
				         "核间迁移 %llu 次，占比过高，放大调度开销", s->migrate_count);
				if (!suggestion)
					suggestion = "检查 CPU affinity 设置；考虑 taskset/cpuset 绑定关键进程";
			}

			// 跳过非异常且 CPU<50% 的进程
			if (!is_anomaly && cpu_pct < 50.0) continue;

			if (diag_count > 0) fprintf(out, ",\n");
			json_indent(out, 4);
			fprintf(out, "{\n");
			snprintf(buf, sizeof(buf), "%s(%u)", procs[i].comm, procs[i].pid);
			json_kv_str(out, 5, "target", buf, 0);
			json_kv_bool(out, 5, "is_anomaly", is_anomaly, 0);
			json_kv_str(out, 5, "subtype", subtype ? subtype : "", 0);
			json_kv_str(out, 5, "root_cause", root_cause ? root_cause : "", 0);
			json_kv_str(out, 5, "suggestion", suggestion ? suggestion : "", 0);

			// key_metrics
			json_obj_begin(out, 5, "key_metrics");
			snprintf(buf, sizeof(buf), "%.1f%%", cpu_pct);
			json_kv_str(out, 6, "CPU 占用", buf, 0);
			snprintf(buf, sizeof(buf), "%.0f/min (主动: %llu, 被动: %llu)",
				 cswitch_pm, s->cswitch_voluntary, s->cswitch_involuntary);
			json_kv_str(out, 6, "上下文切换", buf, 0);
			snprintf(buf, sizeof(buf), "%.0f%%", vol_ratio * 100.0);
			json_kv_str(out, 6, "主动切换占比", buf, 0);
			snprintf(buf, sizeof(buf), "%.1fus / %.1fus", avg_delay_us, max_delay_us);
			json_kv_str(out, 6, "调度延迟 (avg/max)", buf, 0);
			snprintf(buf, sizeof(buf), "%llu 次", s->wakeup_count);
			json_kv_str(out, 6, "唤醒次数", buf, 0);
			if (s->wait_ns > 0 || s->sleep_ns > 0 || s->blocked_ns > 0) {
				if (s->wait_ns > 0) {
					snprintf(buf, sizeof(buf), "%.1f ms", (double)s->wait_ns / 1e6);
					json_kv_str(out, 6, "等待 (runq)", buf, 0);
				}
				if (s->sleep_ns > 0) {
					snprintf(buf, sizeof(buf), "%.1f ms", (double)s->sleep_ns / 1e6);
					json_kv_str(out, 6, "睡眠", buf, 0);
				}
				if (s->blocked_ns > 0) {
					snprintf(buf, sizeof(buf), "%.1f ms", (double)s->blocked_ns / 1e6);
					json_kv_str(out, 6, "阻塞 (I/O等)", buf, 0);
				}
			}
			snprintf(buf, sizeof(buf), "%llu 次", s->migrate_count);
			json_kv_str(out, 6, "核间迁移", buf, 0);
			if (s->futex_wait_count > 0) {
				snprintf(buf, sizeof(buf), "%llu 次, avg %.0fus",
					 s->futex_wait_count, futex_avg_us);
				json_kv_str(out, 6, "futex 等待", buf, 1);
			} else {
				json_kv_str(out, 6, "futex 等待", "无", 1);
			}
			json_obj_end(out, 5, 0);

			// evidence
			json_arr_begin(out, 5, "evidence");
			for (int e = 0; e < ev_count; e++) {
				json_indent(out, 6);
				json_str(out, evidence[e]);
				fprintf(out, "%s\n", e < ev_count - 1 ? "," : "");
			}
			json_arr_end(out, 5, 1);

			diag_count++;
			json_obj_end(out, 4, 1);
		}

		// Close findings — need to remove the trailing comma from last finding
		// We'll handle this with a dummy close approach: the last finding has last=1
		// but we already wrote it with last=0. This is a cosmetic JSON issue fix:
		// We write findings array close manually below.
		json_arr_end(out, 3, 1);
		json_obj_end(out, 2, 1);
	}

	json_arr_end(out, 1, 1);
	fprintf(out, "}\n");
	json_close(out);
	fprintf(stderr, "[*] JSON 报告已写入 %s\n", path);
}

// ─── 用法 ────────────────────────────────────────────────────────
static void usage(const char *prog)
{
	fprintf(stderr,
		"用法: %s [选项]\n"
		"\n"
		"CPU 异常观测工具 —— 基于 eBPF 实时监测进程 CPU 占用、调度延迟和上下文切换，\n"
		"检测异常进程并输出结构化诊断报告。\n"
		"\n"
		"选项:\n"
		"  -i, --interval <秒>      采样间隔（默认: %d）\n"
		"  -d, --duration <秒>      总运行时长，0 表示持续运行（默认: 0）\n"
		"  -o, --output <文件路径>  输出到文件（默认: 标准输出）\n"
		"  -p, --profile <Hz>       栈采样频率，需要 root（默认: %d, 0=禁用）\n"
		"  -s, --schedstats         尝试开启内核调度器详细统计 (sched_schedstats)\n"
		"  --cpu-threshold <%%>      CPU 占用异常阈值，百分比（默认: %.0f）\n"
		"  -h, --help               显示本帮助信息\n"
		"\n"
		"报告默认输出到 report/cpu.json 和 report/cpu.md。\n"
		"\n"
		"示例:\n"
		"  sudo %s                                # 默认参数运行\n"
		"  sudo %s -i 3 -d 60                     # 每 3 秒采样，运行 60 秒\n"
		"  sudo %s -p 99 -o /tmp/report.txt       # 启用栈采样，输出到文件\n"
		"  sudo %s --cpu-threshold 80             # CPU 占用超过 80%% 即视为异常\n"
		"  sudo %s -s                             # 尝试启用内核调度器详细统计\n",
		prog, DEFAULT_INTERVAL, DEFAULT_PROFILE_HZ, DEFAULT_CPU_THRESHOLD,
		prog, prog, prog, prog, prog);
}

// ─── run_cpu ─────────────────────────────────────────────────────
int run_cpu(int argc, char **argv)
{
	int   interval       = DEFAULT_INTERVAL;
	int   duration       = 0;
	int   profile_hz     = DEFAULT_PROFILE_HZ;
	double cpu_threshold = DEFAULT_CPU_THRESHOLD;
	const char *output_file = NULL;

	static struct option long_opts[] = {
		{"interval",      required_argument, 0, 'i'},
		{"duration",      required_argument, 0, 'd'},
		{"output",        required_argument, 0, 'o'},
		{"profile",       required_argument, 0, 'p'},
		{"cpu-threshold", required_argument, 0, 'c'},
		{"schedstats",    no_argument,       0, 's'},
		{"help",          no_argument,       0, 'h'},
		{0, 0, 0, 0}
	};

	int opt;
	int enable_schedstats = 0;
	while ((opt = getopt_long(argc, argv, "i:d:o:p:sh", long_opts, NULL)) != -1) {
		switch (opt) {
		case 'i': interval = atoi(optarg); break;
		case 'd': duration = atoi(optarg); break;
		case 'o': output_file = optarg; break;
		case 'p': profile_hz = atoi(optarg); break;
		case 's': enable_schedstats = 1; break;
		case 'c': cpu_threshold = atof(optarg); break;
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

	libbpf_set_print(print_fn);
	signal(SIGINT, on_signal);
	signal(SIGTERM, on_signal);

	struct cpu_anomaly_bpf *skel = cpu_anomaly_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "无法加载 BPF 程序（需要 root 权限）\n");
		if (output_file) fclose(out);
		return 1;
	}

	if (cpu_anomaly_bpf__attach(skel) != 0) {
		fprintf(stderr, "无法挂载 BPF 程序\n");
		cpu_anomaly_bpf__destroy(skel);
		if (output_file) fclose(out);
		return 1;
	}

	// ── 栈采样 (perf_event) ──
	int *pe_fds = NULL;
	int pe_count = 0;
	int profile_enabled = 0;

	if (profile_hz > 0) {
		pe_fds = calloc(ncpu, sizeof(int));
		if (!pe_fds) {
			fprintf(stderr, "内存分配失败\n");
			cpu_anomaly_bpf__destroy(skel);
			if (output_file) fclose(out);
			return 1;
		}

		struct perf_event_attr attr = {};
		attr.type   = PERF_TYPE_SOFTWARE;
		attr.config = PERF_COUNT_SW_CPU_CLOCK;
		attr.size   = sizeof(attr);
		attr.sample_freq = profile_hz;
		attr.freq   = 1;
		attr.disabled = 1;  // 先禁用，等所有 CPU 准备好再启用

		for (int cpu = 0; cpu < ncpu; cpu++) {
			int fd = perf_event_open(&attr, -1, cpu, -1, PERF_FLAG_FD_CLOEXEC);
			if (fd < 0) {
				fprintf(stderr, "[!] CPU %d perf_event_open 失败: %s\n",
				        cpu, strerror(errno));
				pe_fds[cpu] = -1;
				continue;
			}
			pe_fds[cpu] = fd;

			struct bpf_link *link =
				bpf_program__attach_perf_event(skel->progs.on_profile, fd);
			if (!link) {
				fprintf(stderr, "[!] CPU %d 挂载栈采样失败: %s\n",
				        cpu, strerror(errno));
				close(fd);
				pe_fds[cpu] = -1;
				continue;
			}
			// link 由 skeleton 管理，无需手动释放
			pe_count++;
		}

		if (pe_count > 0) {
			for (int cpu = 0; cpu < ncpu; cpu++) {
				if (pe_fds[cpu] >= 0)
					ioctl(pe_fds[cpu], PERF_EVENT_IOC_ENABLE, 0);
			}
			profile_enabled = 1;
			fprintf(stderr, "[*] 栈采样已启用, %d Hz, %d/%d CPU\n",
			        profile_hz, pe_count, ncpu);
		} else {
			fprintf(stderr, "[*] 栈采样启用失败 (perf_event_paranoid=%d?), 跳过\n",
			        profile_hz);
		}
	}

	int stats_fd   = bpf_map__fd(skel->maps.pid_stats);
	int scounts_fd = bpf_map__fd(skel->maps.stack_counts);
	int stackmap_fd = bpf_map__fd(skel->maps.stackmap);

	fprintf(stderr, "[*] CPU 异常观测已启动, 采样间隔=%ds, CPU 阈值=%.0f%%\n",
	        interval, cpu_threshold);
	fprintf(stderr, "[*] 检测到 %d 个 CPU 核心\n", ncpu);
	if (profile_enabled)
		fprintf(stderr, "[*] 栈采样频率: %d Hz\n", profile_hz);

	if (enable_schedstats) {
		FILE *f = fopen("/proc/sys/kernel/sched_schedstats", "w");
		if (f) {
			fputc('1', f);
			fclose(f);
			fprintf(stderr, "[*] 已开启内核调度器详细统计 (sched_schedstats)\n");
		} else {
			fprintf(stderr,
			        "[!] 无法写入 /proc/sys/kernel/sched_schedstats，请手动执行:\n"
			        "    echo 1 | sudo tee /proc/sys/kernel/sched_schedstats\n");
		}
	}

	char     sched_name[64]     = "未知";
	char     preempt_model[32]  = "未知";
	int      schedstats_on      = 0;
	check_scheduler_info(skel, sched_name, sizeof(sched_name),
	                     preempt_model, sizeof(preempt_model), &schedstats_on);
	fprintf(stderr, "[*] 调度器: %s, 抢占模型: %s, schedstats: %s\n",
	        sched_name, preempt_model, schedstats_on ? "启用" : "未启用");

	time_t start = time(NULL);

	while (!exiting) {
		sleep(interval);

		__u64 interval_ns = (__u64)interval * 1000000000ULL;

		// 收集进程统计
		struct proc_info *procs = NULL;
		int count = 0;
		if (collect_procs(stats_fd, &procs, &count) != 0) {
			fprintf(stderr, "无法读取进程统计数据\n");
			break;
		}

		// 收集栈采样统计
		struct stack_entry *stacks = NULL;
		int stack_count = 0;
		__u64 total_stack_samples = 0;
		if (profile_enabled) {
			collect_stacks(scounts_fd, &stacks, &stack_count,
			               &total_stack_samples);
		}

		// 输出报告
		print_report(out, procs, count, interval_ns,
		             ncpu, cpu_threshold,
		             stacks, stack_count, total_stack_samples,
		             stackmap_fd,
		             sched_name, preempt_model, schedstats_on);


	print_json_report(procs, count, interval_ns,
			  ncpu, cpu_threshold,
			  stacks, stack_count, total_stack_samples,
			  schedstats_on, sched_name, preempt_model,
			  stackmap_fd);
	json_to_markdown("report/cpu.json", "report/cpu.md");

		free(procs);
		free(stacks);

		// 重置统计
		reset_map(stats_fd);
		if (profile_enabled)
			reset_map(scounts_fd);

		if (duration > 0 && time(NULL) - start >= duration)
			break;
	}

	// 禁用并清理 perf events
	if (pe_fds) {
		for (int cpu = 0; cpu < ncpu; cpu++) {
			if (pe_fds[cpu] >= 0) {
				ioctl(pe_fds[cpu], PERF_EVENT_IOC_DISABLE, 0);
				close(pe_fds[cpu]);
			}
		}
		free(pe_fds);
	}

  if (enable_schedstats) 
  {
    // 退出时关闭内核schedstats，防止持续增加内核开销
    FILE *f = fopen("/proc/sys/kernel/sched_schedstats", "w");
		if (f) {
			fputc('0', f);
			fclose(f);
			fprintf(stderr, "[*] 已关闭内核调度器详细统计 (sched_schedstats)\n");
		} else {
			fprintf(stderr,
			        "[!] 无法恢复 /proc/sys/kernel/sched_schedstats，请手动执行:\n"
			        "    echo 0 | sudo tee /proc/sys/kernel/sched_schedstats\n");
		}
  }
	fprintf(stderr, "[*] 正在退出...\n");
	cpu_anomaly_bpf__destroy(skel);
	if (output_file) fclose(out);

	return 0;
}
