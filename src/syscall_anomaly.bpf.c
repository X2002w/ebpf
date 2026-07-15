// syscall_anomaly.bpf.c — 系统调用热点观测 eBPF 内核态
//
// 通过 raw_syscalls tracepoint 追踪所有系统调用:sys_enter: 记录进入时间戳 + nr
// sys_exit:  结算耗时、错误计数

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// 系统调用跟踪
struct sys_enter_info {
	__u64 enter_ts;
	__u32 nr;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, __u32);               // TID
	__type(value, struct sys_enter_info);
} sys_enter_ts SEC(".maps");

// 全局 per-系统调用统计
struct syscall_stats {
	__u64 count;
	__u64 total_ns;
	__u64 max_ns;
	__u64 err_count;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 512);
	__type(key, __u32);       // 系统调用号
	__type(value, struct syscall_stats);
} sys_stats SEC(".maps");

// 每个线程分别对每个系统调用的调用情况和耗时
// key: 高 32 位 TID, 低 32 位 nr
struct pid_nr_stats {
	__u64 count;
	__u64 total_ns;
	__u64 max_ns;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, __u64);               // (tid << 32) | nr
	__type(value, struct pid_nr_stats);
} pid_nr_stats SEC(".maps");

static inline struct syscall_stats *get_sys_stats(__u32 nr)
{
	struct syscall_stats *s = bpf_map_lookup_elem(&sys_stats, &nr);
	if (!s) {
		struct syscall_stats zero = {};
		bpf_map_update_elem(&sys_stats, &nr, &zero, BPF_ANY);
		s = bpf_map_lookup_elem(&sys_stats, &nr);
    if (!s) return 0;
	}
	return s;
}

static inline struct pid_nr_stats *get_pid_nr_stats(__u32 tid, __u32 nr)
{
	__u64 key = ((__u64)tid << 32) | nr;
	struct pid_nr_stats *s = bpf_map_lookup_elem(&pid_nr_stats, &key);
	if (!s) {
		struct pid_nr_stats zero = {};
		bpf_map_update_elem(&pid_nr_stats, &key, &zero, BPF_ANY);
		s = bpf_map_lookup_elem(&pid_nr_stats, &key);
    if (!s) return 0;
	}
	return s;
}

SEC("tp/raw_syscalls/sys_enter")
int on_sys_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 tid = (__u32)pid_tgid;
	__u32 nr  = (__u32)ctx->id;

	__u64 now = bpf_ktime_get_ns();

	struct sys_enter_info info = { .enter_ts = now, .nr = nr };
	bpf_map_update_elem(&sys_enter_ts, &tid, &info, BPF_ANY);

	return 0;
}

SEC("tp/raw_syscalls/sys_exit")
int on_sys_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 tid = (__u32)pid_tgid;

	struct sys_enter_info *info = bpf_map_lookup_elem(&sys_enter_ts, &tid);
	if (!info)
		return 0;

	__u64 now = bpf_ktime_get_ns();
	__u64 duration = now - info->enter_ts;
	__u32 nr = info->nr;

	bpf_map_delete_elem(&sys_enter_ts, &tid);

	// 全局 per-nr 统计
	struct syscall_stats *gs = get_sys_stats(nr);
  if (!gs)
    return 0;

  __sync_fetch_and_add(&gs->count, 1);
  __sync_fetch_and_add(&gs->total_ns, duration);
  if (duration > gs->max_ns)
    gs->max_ns = duration;
  if (ctx->ret < 0)
    __sync_fetch_and_add(&gs->err_count, 1);

	// 线程对应的系统调用统计
	struct pid_nr_stats *ps = get_pid_nr_stats(tid, nr);
  if (!ps) 
    return 0;

  __sync_fetch_and_add(&ps->count, 1);
  __sync_fetch_and_add(&ps->total_ns, duration);
  if (duration > ps->max_ns)
    ps->max_ns = duration;

	return 0;
}
