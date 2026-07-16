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
#include "../include/utils.h"

#define DEFAULT_INTERVAL    5
#define FREQ_WARN_PER_SEC   10000
#define LAT_WARN_US         10000
#define ERR_RATE_WARN       0.1

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
	static const char *table[] = {
		[0]   = "read",         [1]   = "write",
		[2]   = "open",         [3]   = "close",
		[4]   = "stat",         [5]   = "fstat",
		[6]   = "lstat",        [7]   = "poll",
		[8]   = "lseek",        [9]   = "mmap",
		[10]  = "mprotect",     [11]  = "munmap",
		[12]  = "brk",          [13]  = "rt_sigaction",
		[14]  = "rt_sigprocmask", [15] = "rt_sigreturn",
		[16]  = "ioctl",        [17]  = "pread64",
		[18]  = "pwrite64",     [19]  = "readv",
		[20]  = "writev",       [21]  = "access",
		[22]  = "pipe",         [23]  = "select",
		[24]  = "sched_yield",  [25]  = "mremap",
		[27]  = "mincore",      [28]  = "madvise",
		[29]  = "shmget",       [30]  = "shmat",
		[32]  = "dup",          [33]  = "dup2",
		[35]  = "nanosleep",    [39]  = "getpid",
		[41]  = "socket",       [42]  = "connect",
		[43]  = "accept",       [44]  = "sendto",
		[45]  = "recvfrom",     [46]  = "sendmsg",
		[47]  = "recvmsg",      [49]  = "bind",
		[50]  = "listen",       [51]  = "getsockname",
		[54]  = "setsockopt",   [55]  = "getsockopt",
		[56]  = "clone",        [57]  = "fork",
		[59]  = "execve",       [60]  = "exit",
		[61]  = "wait4",        [62]  = "kill",
		[72]  = "fcntl",        [73]  = "flock",
		[74]  = "fsync",        [75]  = "fdatasync",
		[78]  = "getdents",     [79]  = "getcwd",
		[80]  = "chdir",        [82]  = "rename",
		[83]  = "mkdir",        [84]  = "rmdir",
		[85]  = "creat",        [87]  = "unlink",
		[96]  = "gettimeofday", [97]  = "getrlimit",
		[102] = "getuid",       [104] = "getgid",
		[131] = "sigaltstack",  [137] = "statfs",
		[157] = "prctl",        [158] = "arch_prctl",
		[160] = "setrlimit",    [165] = "mount",
		[186] = "gettid",       [202] = "futex",
		[203] = "sched_setaffinity", [204] = "sched_getaffinity",
		[213] = "epoll_create", [217] = "getdents64",
		[228] = "clock_gettime", [229] = "clock_getres",
		[230] = "clock_nanosleep", [231] = "exit_group",
		[232] = "epoll_wait",   [233] = "epoll_ctl",
		[234] = "tgkill",       [257] = "openat",
		[262] = "newfstatat",   [263] = "unlinkat",
		[264] = "renameat",     [265] = "linkat",
		[267] = "readlinkat",   [270] = "pselect6",
		[271] = "ppoll",        [273] = "set_robust_list",
		[281] = "epoll_pwait",  [284] = "eventfd",
		[285] = "fallocate",    [291] = "epoll_create1",
		[298] = "perf_event_open", [302] = "prlimit64",
		[314] = "sched_setattr", [318] = "getrandom",
		[319] = "memfd_create", [321] = "bpf",
		[322] = "execveat",     [332] = "statx",
		[334] = "rseq",         [435] = "clone3",
		[436] = "close_range",  [437] = "openat2",
		[438] = "pidfd_getfd",  [439] = "faccessat2",
		[440] = "process_madvise", [441] = "epoll_pwait2",
	};

	if (nr < sizeof(table) / sizeof(table[0]) && table[nr])
		return table[nr];

	static char buf[32];
	snprintf(buf, sizeof(buf), "syscall_%u", nr);
	return buf;
}

static int is_wait_syscall(unsigned int nr)
{
	switch (nr) {
	case 7:   // poll
	case 23:  // select
	case 35:  // nanosleep
	case 230: // clock_nanosleep
	case 232: // epoll_wait
	case 270: // pselect6
	case 271: // ppoll
	case 281: // epoll_pwait
	case 441: // epoll_pwait2
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
		const char *flag = rate > FREQ_WARN_PER_SEC ? " <-- 高频" : "";
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
		const char *flag = avg_us > LAT_WARN_US ? " <-- 高耗时" : "";
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

		if (rate <= FREQ_WARN_PER_SEC && avg_us <= LAT_WARN_US && err_pct <= ERR_RATE_WARN * 100)
			continue;

		diag_count++;
		fprintf(out, "\n  [%d] %s", diag_count, syscall_name(entries[i].nr));

		const char *type = NULL;
		if (rate > FREQ_WARN_PER_SEC && avg_us > LAT_WARN_US)
			type = "高频 + 高耗时";
		else if (rate > FREQ_WARN_PER_SEC)
			type = "高频调用";
		else if (avg_us > LAT_WARN_US)
			type = "高耗时";
		else
			type = "高错误率";
		fprintf(out, "  —  %s\n", type);

		fprintf(out, "      调用次数: %llu (%.0f/s)  |  平均耗时: %.0fus  |  最大耗时: %.1fms\n",
		        s->count, rate, avg_us, (double)s->max_ns / 1e6);
		if (err_pct > 0)
			fprintf(out, "      错误率: %.1f%% (%llu/%llu)\n", err_pct, s->err_count, s->count);

		if (rate > FREQ_WARN_PER_SEC && avg_us <= LAT_WARN_US)
			fprintf(out,
			        "      疑似根因: 事件循环或 busy-poll 导致短耗时系统调用高频重复\n"
			        "      建议: 检查轮询逻辑，改用阻塞+超时或事件驱动模式\n");
		else if (avg_us > LAT_WARN_US && is_wait_syscall(entries[i].nr))
			fprintf(out,
			        "      疑似根因: 事件等待型系统调用，高耗时说明无事件到达或超时设置较长\n"
			        "      建议: 属正常等待行为；若期望快速响应，检查 fd 活跃度和超时参数\n");
		else if (avg_us > LAT_WARN_US)
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

		if (rate <= FREQ_WARN_PER_SEC && avg_us <= LAT_WARN_US)
			continue;

		pdiag++;
		fprintf(out, "\n  [进程%d] TID %u (%s)  —  %s\n",
		        pdiag, p->tid, p->comm,
		        avg_us > LAT_WARN_US ? "高耗时" : "高频调用");
		fprintf(out, "      系统调用总数: %llu (%.0f/s)  |  平均耗时: %.0fus\n",
		        p->total_count, rate, avg_us);
		fprintf(out, "      最多调用: %s (%llu次)  |  耗时最多: %s (%.1fms)\n",
		        syscall_name(p->top_nr), p->top_nr_count,
		        syscall_name(p->top_lat_nr), (double)p->top_lat_ns / 1e6);

		if (avg_us > LAT_WARN_US && is_wait_syscall(p->top_lat_nr))
			fprintf(out,
			        "      疑似根因: 线程主要时间在事件等待 (%s)，属正常 I/O 多路复用行为\n"
			        "      建议: 无明显异常；若需降低时延，检查 fd 活跃度或调小超时\n",
			        syscall_name(p->top_lat_nr));
		else if (avg_us > LAT_WARN_US)
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
		"  -h, --help               显示本帮助信息\n"
		"\n"
		"示例:\n"
		"  sudo %s                       # 默认参数运行\n"
		"  sudo %s -i 3 -d 60            # 每 3 秒采样，运行 60 秒\n",
		prog, DEFAULT_INTERVAL, prog, prog);
}

int run_syscall(int argc, char **argv)
{
	int interval = DEFAULT_INTERVAL;
	int duration = 0;
	const char *output_file = NULL;

	static struct option long_opts[] = {
		{"interval", required_argument, 0, 'i'},
		{"duration", required_argument, 0, 'd'},
		{"output",   required_argument, 0, 'o'},
		{"help",     no_argument,       0, 'h'},
		{0, 0, 0, 0}
	};

	int opt;
	while ((opt = getopt_long(argc, argv, "i:d:o:h", long_opts, NULL)) != -1) {
		switch (opt) {
		case 'i': interval = atoi(optarg); break;
		case 'd': duration = atoi(optarg); break;
		case 'o': output_file = optarg; break;
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

		free(entries);
		free(pids);

		reset_map(sys_stats_fd);
		reset_u64_map(pid_nr_stats_fd);

		if (duration > 0 && time(NULL) - start >= duration)
			break;
	}

	fprintf(stderr, "[*] 正在退出...\n");
	syscall_anomaly_bpf__destroy(skel);
	if (output_file) fclose(out);
	return 0;
}
