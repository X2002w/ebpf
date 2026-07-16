#ifndef UTILS_H
#define UTILS_H

#include <signal.h>
#include <stddef.h>
#include <sys/types.h>

struct perf_event_attr;

// 系统全局负载指标
struct sys_metrics {
	// 系统 1, 5, 15 分钟平均负载
	double load1, load5, load15;

	// 瞬时 run queue 深度，正在运行或可运行的进程数
	int procs_running;

	// 当前被阻塞的进程数 (wait IO)
	int procs_blocked;
};

extern volatile sig_atomic_t exiting;

void on_signal(int sig);
void iso_timestamp(char *buf, size_t len);
void read_comm(unsigned int pid, char *buf, size_t len);
void read_sys_metrics(struct sys_metrics *m);
void resolve_ip(pid_t pid, unsigned long long ip, char *out_buf, size_t len);
void reset_map(int map_fd);
int perf_event_open(struct perf_event_attr *attr, pid_t pid,
                    int cpu, int group_fd, unsigned long flags);

#endif
