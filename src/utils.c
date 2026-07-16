#include "../include/utils.h"
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <bpf/bpf.h>

volatile sig_atomic_t exiting;

void on_signal(int sig) { (void)sig; exiting = 1; }

void iso_timestamp(char *buf, size_t len)
{
	time_t now = time(NULL);
	struct tm tm;
	localtime_r(&now, &tm);
	strftime(buf, len, "%Y-%m-%dT%H:%M:%S", &tm);
}

// 读取 /proc/<pid>/comm
void read_comm(unsigned int pid, char *buf, size_t len)
{
	char path[64];
	snprintf(path, sizeof(path), "/proc/%u/comm", pid);
	FILE *f = fopen(path, "r");
	if (!f) {
		snprintf(buf, len, "<exited>");
		return;
	}

	if (fgets(buf, len, f))
		buf[strcspn(buf, "\n")] = '\0';
	else
		snprintf(buf, len, "<?>");
	fclose(f);
}

// 读取系统负载与进程运行/阻塞数
void read_sys_metrics(struct sys_metrics *m)
{
	memset(m, 0, sizeof(*m));

	FILE *f = fopen("/proc/loadavg", "r");
	if (f) {
		int running = 0, total = 0;
		fscanf(f, "%lf %lf %lf %d/%d",
		       &m->load1, &m->load5, &m->load15, &running, &total);
		fclose(f);
	}

	// /proc/stat 提供更精确的瞬时值
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

// 通过 /proc/<pid>/maps 将指令地址解析为 模块名+偏移
void resolve_ip(pid_t pid, unsigned long long ip, char *out_buf, size_t len)
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
		// /proc/pid/maps 数据格式: start-end perms offset dev inode [name]
		int n = sscanf(line, "%lx-%lx %7s %lx %*x:%*x %ld %255s",
		               &start, &end, perms, &offset, &inode, name);
		if (n < 3) continue;

		if (ip >= start && ip < end) {
			if (n >= 5 && name[0] != '\0')
				snprintf(out_buf, len, "%s+0x%llx", name,
				         (unsigned long long)(ip - start));
			else if (inode == 0)
				snprintf(out_buf, len, "[vdso/vvar] 0x%llx", ip);
			else
				snprintf(out_buf, len, "[anon:%lx] 0x%llx", inode, ip);
			fclose(f);
			return;
		}
	}
	fclose(f);
	snprintf(out_buf, len, "0x%llx", ip);
}

// 清空 u32 key 的 BPF map
void reset_map(int map_fd)
{
	unsigned int key = 0, next;
	while (bpf_map_get_next_key(map_fd, &key, &next) == 0) {
		bpf_map_delete_elem(map_fd, &next);
		key = next;
	}
}

// perf_event_open 系统调用封装
int perf_event_open(struct perf_event_attr *attr, pid_t pid,
                    int cpu, int group_fd, unsigned long flags)
{
	return syscall(__NR_perf_event_open, attr, pid, cpu, group_fd, flags);
}
