/* report_md.c — 生成 Markdown 格式的系统诊断报告
 *
 * 输出结构化 Markdown 报告，包含系统概览、进程指标表格、
 * 异常诊断详情、证据链、栈采样结果。
 * 默认输出到 report.md，无需 CLI 参数即可启用。
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "report_md.h"

#define DEFAULT_OUTPUT "report/report.md"

// 阈值常量 (与 cpu_anomaly.c 保持一致) 
#define CSWITCH_WARN_PER_MIN  30000
#define CSWITCH_CRIT_PER_MIN  50000
#define SCHED_DELAY_WARN_US   5000
#define SCHED_DELAY_CRIT_US   20000
#define BUSYLOOP_CS_PER_MIN   5000
#define STACK_CONC_RATIO      0.8
#define VOLUNTARY_RATIO_HIGH  0.5

// 数据结构 (与 BPF 侧一致)
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

struct proc_info {
	unsigned int pid;
	char comm[16];
	struct pid_stats stats;
};

struct stack_entry {
	int stack_id;
	unsigned long long count;
};

struct sys_metrics {
	double load1, load5, load15;
	int procs_running;
	int procs_blocked;
};


// 读取时间
static void iso_timestamp(char *buf, size_t len)
{
	time_t now = time(NULL);
	struct tm tm;
	localtime_r(&now, &tm);
	strftime(buf, len, "%Y-%m-%dT%H:%M:%S", &tm);
}

// 读取系统统计数据
static void read_sys_metrics(struct sys_metrics *m)
{
	memset(m, 0, sizeof(*m));
	FILE *f = fopen("/proc/loadavg", "r");
	if (f) {
		int running = 0, total = 0;
		fscanf(f, "%lf %lf %lf %d/%d",
		       &m->load1, &m->load5, &m->load15, &running, &total);
		fclose(f);
	}
	f = fopen("/proc/stat", "r");
	if (f) {
		char line[128];
		while (fgets(line, sizeof(line), f)) {
			if (sscanf(line, "procs_running %d", &m->procs_running) == 1)
				continue;
			if (sscanf(line, "procs_blocked %d", &m->procs_blocked) == 1)
				break;
		}
		fclose(f);
	}
}

// 定位调用栈ip
static void resolve_ip(int pid, unsigned long long ip, char *out_buf, size_t len)
{
	char path[64];
	snprintf(path, sizeof(path), "/proc/%d/maps", pid);
	FILE *f = fopen(path, "r");
	if (!f) {
		snprintf(out_buf, len, "0x%llx", ip);
		return;
	}
	char line[512];
	while (fgets(line, sizeof(line), f)) {
		unsigned long start, end, offset, inode;
		char perms[8], name[256] = "";
		int n = sscanf(line, "%lx-%lx %7s %lx %*x:%*x %ld %255s",
			       &start, &end, perms, &offset, &inode, name);
		if (n < 3) continue;
		if (ip >= start && ip < end) {
			if (n >= 5 && name[0] != '\0')
				snprintf(out_buf, len, "`%s+0x%llx`", name,
					 (unsigned long long)(ip - start));
			else
				snprintf(out_buf, len, "0x%llx", ip);
			fclose(f);
			return;
		}
	}
	fclose(f);
	snprintf(out_buf, len, "0x%llx", ip);
}

static int cmp_cpu(const void *a, const void *b)
{
	const struct proc_info *pa = a, *pb = b;
	double ca = (double)pa->stats.on_cpu_ns;
	double cb = (double)pb->stats.on_cpu_ns;
	return (cb > ca) - (ca > cb);
}

static int cmp_stack(const void *a, const void *b)
{
	const struct stack_entry *sa = a, *sb = b;
	return (sb->count > sa->count) - (sa->count > sb->count);
}

// Markdown 转义 
static void md_escape(FILE *out, const char *s)
{
	for (; *s; s++) {
		switch (*s) {
		case '|':  fputs("\\|", out); break;
		case '\n': fputs("<br>", out); break;
		default:   fputc(*s, out);
		}
	}
}

// 生成md 报告
void print_markdown_report(const char *path,
                           struct proc_info *procs, int count,
                           unsigned long long total_interval_ns,
                           int ncpu, double cpu_threshold,
                           struct stack_entry *stacks, int stack_count,
                           unsigned long long total_stack_samples,
                           int stackmap_fd,
                           const char *sched_name, const char *preempt_model,
                           int schedstats_on)
{
  // 打开目标写入文件
	const char *out_path = path ? path : DEFAULT_OUTPUT;

	// 确保 report/ 目录存在 
	FILE *out = fopen(out_path, "w");
	if (!out) {
		mkdir("report", 0755);
		out = fopen(out_path, "w");
	}
	if (!out) {
		fprintf(stderr, "[!] 无法写入 %s\n", out_path);
		return;
	}

	char ts[32];
	iso_timestamp(ts, sizeof(ts));
	double duration_s = (double)total_interval_ns / 1e9;

	struct sys_metrics sys;
	read_sys_metrics(&sys);

  // 标题
	fprintf(out, "# CPU 异常观测诊断报告\n\n");
	fprintf(out, "| 项目 | 内容 |\n");
	fprintf(out, "|------|------|\n");
	fprintf(out, "| **异常时间窗口** | %s |\n", ts);
	fprintf(out, "| **采样间隔** | %.1fs |\n\n", duration_s);

  // 系统概览
	fprintf(out, "## 系统概览\n\n");
	fprintf(out, "| 指标 | 数值 |\n");
	fprintf(out, "|------|------|\n");
	fprintf(out, "| CPU 核心数 | %d |\n", ncpu);
	fprintf(out, "| 活跃进程数 | %d |\n", count);
	fprintf(out, "| 调度器 | %s |\n", sched_name);
	fprintf(out, "| 抢占模型 | %s |\n", preempt_model);
	fprintf(out, "| schedstats | %s |\n", schedstats_on ? "启用 (精确核算)" : "未启用 (挂墙时间)");
	fprintf(out, "| 系统负载 (1m/5m/15m) | %.2f / %.2f / %.2f |\n",
	       sys.load1, sys.load5, sys.load15);
	fprintf(out, "| RunQ 深度 (瞬时) | %d |\n", sys.procs_running);
	fprintf(out, "| 不可中断阻塞 | %d |\n", sys.procs_blocked);
	fprintf(out, "| CPU 异常阈值 | %.0f%% |\n\n", cpu_threshold);

  // 栈采样概要
	if (total_stack_samples > 0 && stack_count > 0) {
		qsort(stacks, stack_count, sizeof(struct stack_entry), cmp_stack);
		fprintf(out, "## 栈采样概要\n\n");
		fprintf(out, "总采样: **%llu** 次\n\n", total_stack_samples);
		fprintf(out, "| 排名 | Stack ID | 采样次数 | 占比 |\n");
		fprintf(out, "|------|----------|----------|------|\n");
		int top_n = stack_count < 5 ? stack_count : 5;
		int resolve_pid = (count > 0) ? procs[0].pid : 0;
		for (int i = 0; i < top_n; i++) {
			fprintf(out, "| %d | %d | %llu | %.1f%% |\n",
			       i + 1, stacks[i].stack_id, stacks[i].count,
			       (double)stacks[i].count / (double)total_stack_samples * 100.0);
		}
		fprintf(out, "\n");

    // 展开调用栈
		for (int i = 0; i < top_n; i++) {
			fprintf(out, "<details>\n<summary>Stack #%d 详情</summary>\n\n```\n",
			       i + 1);
			unsigned long long ips[127];
			memset(ips, 0, sizeof(ips));
			if (bpf_map_lookup_elem(stackmap_fd, &stacks[i].stack_id, ips) == 0) {
				int depth = 0;
				while (depth < 127 && ips[depth] != 0) depth++;
				for (int d = 0; d < depth; d++) {
					char sym[256];
					resolve_ip(resolve_pid, ips[d], sym, sizeof(sym));
					fprintf(out, "  #%-2d  %s\n", d, sym);
				}
			}
			fprintf(out, "```\n</details>\n\n");
		}
	}

  // TOP 进程指标 
	fprintf(out, "## TOP 进程指标\n\n");
	fprintf(out, "| PID | 进程名 | CPU%% | 切换/min | 主动 | 被动 | "
	       "调度延迟(avg) | 调度延迟(max) | 迁移 | futex | 状态 |\n");
	fprintf(out, "|-----|--------|------|----------|------|------|"
	       "---------------|---------------|------|-------|------|\n");

	qsort(procs, count, sizeof(struct proc_info), cmp_cpu);
	int limit = count < 20 ? count : 20;

	for (int i = 0; i < limit; i++) {
		struct pid_stats *s = &procs[i].stats;
		unsigned long long cpu_ns = (schedstats_on && s->cpu_runtime_ns > 0)
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

		// 判定异常 
		double vol_ratio = (s->cswitch_total > 0)
			? (double)s->cswitch_voluntary / (double)s->cswitch_total : 0;
		double stack_concentration = 0;
		if (total_stack_samples > 0 && stack_count > 0)
			stack_concentration = (double)stacks[0].count /
					      (double)total_stack_samples;

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

		fprintf(out, "| %u | ", procs[i].pid);
		md_escape(out, procs[i].comm);
		fprintf(out, " | %.1f | %.0f | %llu | %llu | %.0fus | %.0fus | %llu | %llu | %s |\n",
		       cpu_pct, cswitch_pm,
		       s->cswitch_voluntary, s->cswitch_involuntary,
		       avg_delay_us, max_delay_us,
		       s->migrate_count, s->futex_wait_count,
		       status);
	}
	fprintf(out, "\n");

  // 异常进程诊断分析 -> 与cpu_anomaly 诊断方式相同
	int anomaly_seq = 0;
	for (int i = 0; i < limit; i++) {
		struct pid_stats *s = &procs[i].stats;
		unsigned long long cpu_ns = (schedstats_on && s->cpu_runtime_ns > 0)
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

		double stack_concentration = 0;
		if (total_stack_samples > 0 && stack_count > 0)
			stack_concentration = (double)stacks[0].count /
					      (double)total_stack_samples;

		// 根因分类
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
				suggestion = "perf top 定位到具体函数后检查循环退出条件；"
				             "考虑添加 usleep/yield";
			} else if (cswitch_pm < BUSYLOOP_CS_PER_MIN &&
			           total_stack_samples == 0) {
				subtype = "CPU异常占用 (疑为 busy loop)";
				root_cause = "进程切换频率极低 (< 5000/min)，疑似 busy loop；"
				             "建议启用栈采样确认";
				suggestion = "使用 -p 启用栈采样定位热点函数；或使用 perf top 观察";
			} else if (s->cswitch_involuntary > s->cswitch_voluntary * 10) {
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
			} else {
				subtype = "CPU异常占用";
				root_cause = "进程持续高 CPU 占用，疑似计算热点或 busy loop";
				suggestion = "使用 perf top/flamegraph 分析热点函数；"
				             "考虑 cgroup CPU limit 隔离";
			}
		}

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

		anomaly_seq++;
		fprintf(out, "## [%d] PID %u — %s\n\n",
		       anomaly_seq, procs[i].pid, procs[i].comm);

		fprintf(out, "**状态**: %s", is_anomaly ? "🔴 异常" : "🟢 正常");
		if (subtype) fprintf(out, " — *%s*", subtype);
		fprintf(out, "\n\n");

		// 关键指标 
		fprintf(out, "### 关键指标\n\n");
		fprintf(out, "| 指标 | 数值 |\n");
		fprintf(out, "|------|------|\n");
		fprintf(out, "| CPU 占用 | **%.1f%%** |\n", cpu_pct);
		fprintf(out, "| 上下文切换 | %.0f/min (主动: %llu, 被动: %llu) |\n",
		       cswitch_pm, s->cswitch_voluntary, s->cswitch_involuntary);
		fprintf(out, "| 主动切换占比 | %.0f%% |\n", vol_ratio * 100.0);
		fprintf(out, "| 调度延迟 (avg/max) | %.1fus / %.1fus |\n",
		       avg_delay_us, max_delay_us);
		fprintf(out, "| 唤醒次数 | %llu |\n", s->wakeup_count);

		if (s->wait_ns > 0 || s->sleep_ns > 0 || s->blocked_ns > 0) {
			fprintf(out, "| 等待 (runq) | %.1f ms |\n",
			       (double)s->wait_ns / 1e6);
			fprintf(out, "| 睡眠 | %.1f ms |\n",
			       (double)s->sleep_ns / 1e6);
			fprintf(out, "| 阻塞 (I/O等) | %.1f ms |\n",
			       (double)s->blocked_ns / 1e6);
		}

		fprintf(out, "| 核间迁移 | %llu 次 |\n", s->migrate_count);
		if (s->futex_wait_count > 0)
			fprintf(out, "| futex 等待 | %llu 次, avg %.0fus |\n",
			       s->futex_wait_count, futex_avg_us);
		fprintf(out, "\n");

		// 诊断证据
		if (is_anomaly && ev_count > 0) {
			fprintf(out, "### 诊断证据\n\n");
			for (int e = 0; e < ev_count; e++)
				fprintf(out, "- %s\n", evidence[e]);
			fprintf(out, "\n");
		}

		// 根因 & 建议 
		if (root_cause)
			fprintf(out, "### 疑似根因\n\n> %s\n\n", root_cause);
		if (suggestion)
			fprintf(out, "### 建议\n\n> %s\n\n", suggestion);

		fprintf(out, "---\n\n");
	}

	if (anomaly_seq == 0)
		fprintf(out, "> 采样窗口内无异常进程，系统运行正常。\n\n");

	fclose(out);
	fprintf(stderr, "[*] Markdown 报告已写入 %s\n", out_path);
}
