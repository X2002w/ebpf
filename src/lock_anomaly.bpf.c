// lock_anomaly.bpf.c — 锁竞争异常观测 eBPF 内核态
//
// 仅包含 futex 独有的追踪逻辑:
//   - 记录 uaddr 用于 per-futex-key 热点锁聚合
//   - 在 futex 等待点捕获用户态调用栈 (off-CPU 维度)
//
// sched_switch / sched_stat_blocked / on-CPU 数据复用 cpu_anomaly skeleton

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// Per-futex-key 热点锁统计 — key = (tgid, uaddr) 唯一标识进程内的一把锁
struct lock_futex_key {
	__u32 tgid;
	__u64 uaddr;
};

struct futex_hot_stats {
	__u64 wait_ns;
	__u64 wait_count;
	__u64 max_wait_ns;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, struct lock_futex_key);
	__type(value, struct futex_hot_stats);
} futex_key_stats SEC(".maps");

// Per-PID futex 聚合 (lock 模块独立统计)
struct lock_pid_stats {
	__u64 futex_wait_ns;
	__u64 futex_wait_count;
	__u64 futex_max_wait_ns;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, __u32);            // TID
	__type(value, struct lock_pid_stats);
} lock_pid_stats SEC(".maps");

// Futex 等待跟踪 (per‑tid)
struct futex_wait_val {
	__u64 ts;
	__u64 uaddr;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, __u32);            // TID
	__type(value, struct futex_wait_val);
} lock_futex_ts SEC(".maps");

// 等待点调用栈采样
struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__uint(max_entries, 10240);
	__type(key, __u32);
	__type(value, __u64[127]);
} lock_stackmap SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, __u32);    // stack_id
	__type(value, __u64);  // 等待点命中次数
} lock_stack_counts SEC(".maps");

// 辅助
static inline struct futex_hot_stats *get_futex_key_stats(__u32 tgid, __u64 uaddr)
{
	struct lock_futex_key key = { .tgid = tgid, .uaddr = uaddr };
	struct futex_hot_stats *s = bpf_map_lookup_elem(&futex_key_stats, &key);
	if (!s) {
		struct futex_hot_stats zero = {};
		bpf_map_update_elem(&futex_key_stats, &key, &zero, BPF_ANY);
		s = bpf_map_lookup_elem(&futex_key_stats, &key);
    if (!s) return 0;
	}
	return s;
}

static inline struct lock_pid_stats *get_lock_pid_stats(__u32 tid)
{
	struct lock_pid_stats *s = bpf_map_lookup_elem(&lock_pid_stats, &tid);
	if (!s) {
		struct lock_pid_stats zero = {};
		bpf_map_update_elem(&lock_pid_stats, &tid, &zero, BPF_ANY);
		s = bpf_map_lookup_elem(&lock_pid_stats, &tid);
    if (!s) return 0;
	}
	return s;
}

// sys_enter_futex: 记录 FUTEX_WAIT 进入点
SEC("tp/syscalls/sys_enter_futex")
int on_sys_enter_futex(struct trace_event_raw_sys_enter *ctx)
{
	// FUTEX_WAIT=0, FUTEX_WAIT_PRIVATE=128
  // op = 0: 进程间共享锁陷入内核
  // op = 128: 线程争用进程内线程锁陷入内核

  // 仅关注进程间共享锁
	if ((ctx->args[1] & 0x7f) != 0)
		return 0;

	__u64 pid_tgid = bpf_get_current_pid_tgid();
  // 获取线程 ID
	__u32 tid = (__u32)pid_tgid;

	__u64 now = bpf_ktime_get_ns();
	__u64 uaddr = ctx->args[0];

	struct futex_wait_val val = { .ts = now, .uaddr = uaddr };
	bpf_map_update_elem(&lock_futex_ts, &tid, &val, BPF_ANY);

	// 在等待点捕获用户态调用栈 — 定位哪些代码路径在争锁
	__s32 stack_id = bpf_get_stackid(ctx, &lock_stackmap, BPF_F_USER_STACK);
	if (stack_id >= 0) {
		__u64 *count = bpf_map_lookup_elem(&lock_stack_counts, &stack_id);
		if (count)
			__sync_fetch_and_add(count, 1);
		else {
			__u64 one = 1;
			bpf_map_update_elem(&lock_stack_counts, &stack_id, &one, BPF_ANY);
		}
	}

	return 0;
}

// sys_exit_futex: 结算等待时间
SEC("tp/syscalls/sys_exit_futex")
int on_sys_exit_futex(struct trace_event_raw_sys_exit *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 tid = (__u32)pid_tgid;
	__u32 tgid = (__u32)(pid_tgid >> 32);

	struct futex_wait_val *wv = bpf_map_lookup_elem(&lock_futex_ts, &tid);
	if (!wv)
		return 0;

	__u64 now = bpf_ktime_get_ns();
	__u64 wait_ns = now - wv->ts;

	// per‑PID 统计
	struct lock_pid_stats *ps = get_lock_pid_stats(tid);
	if (ps) {
		__sync_fetch_and_add(&ps->futex_wait_ns, wait_ns);
		__sync_fetch_and_add(&ps->futex_wait_count, 1);
		if (wait_ns > ps->futex_max_wait_ns)
			ps->futex_max_wait_ns = wait_ns;
	}

	// per‑futex‑key 热点锁聚合
	if (wv->uaddr != 0) {
		struct futex_hot_stats *fs = get_futex_key_stats(tgid, wv->uaddr);
		if (fs) {
			__sync_fetch_and_add(&fs->wait_ns, wait_ns);
			__sync_fetch_and_add(&fs->wait_count, 1);
			if (wait_ns > fs->max_wait_ns)
				fs->max_wait_ns = wait_ns;
		}
	}

	bpf_map_delete_elem(&lock_futex_ts, &tid);
	return 0;
}
