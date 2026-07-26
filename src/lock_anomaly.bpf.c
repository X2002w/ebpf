// lock_anomaly.bpf.c — 锁竞争异常观测 eBPF 内核态
//
// 自包含设计: 不依赖 cpu_anomaly skeleton, 自行采集 sched_switch / sched_stat_blocked
// 填充 pid_stats (on_cpu_ns / cswitch_* / blocked_ns), 避免 ARM64 双 skeleton
// 同时 attach futex tracepoint 时的 libbpf destroy 段错误
//
// futex 独有:
//   - 记录 uaddr 用于 per-futex-key 热点锁聚合
//   - 在 futex 等待点捕获用户态调用栈 (off-CPU 维度)

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "../include/bpf_shared.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define TASK_RUNNING 0

// Per-PID 聚合 (复用 bpf_shared.h 的 pid_stats, 仅填锁模块需要的字段)
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, __u32);
	__type(value, struct pid_stats);
} pid_stats SEC(".maps");

// 每个 CPU 当前运行任务 + 切入时间戳
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct cpu_task_info);
} cpu_task SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, struct lock_futex_key);
	__type(value, struct futex_hot_stats);
} futex_key_stats SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, __u32);            // TID
	__type(value, struct lock_pid_stats);
} lock_pid_stats SEC(".maps");

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

// sched_switch: 累积 on_cpu_ns / cswitch_*, 仅这 4 个字段被锁模块用户态读取
SEC("tp/sched/sched_switch")
int on_sched_switch(struct trace_event_raw_sched_switch *ctx)
{
	__u32 prev_pid = ctx->prev_pid;
	__u32 next_pid = ctx->next_pid;
	__u64 now = bpf_ktime_get_ns();
	__u32 zero = 0;

	struct cpu_task_info *task = bpf_map_lookup_elem(&cpu_task, &zero);
	if (!task)
		return 0;

	if (task->pid == prev_pid && prev_pid != 0) {
		__u64 delta = now - task->ts;
		struct pid_stats *s = bpf_map_lookup_elem(&pid_stats, &prev_pid);
		if (s) {
			s->on_cpu_ns += delta;
			s->cswitch_total++;
			if (ctx->prev_state == TASK_RUNNING)
				s->cswitch_involuntary++;
			else
				s->cswitch_voluntary++;
		} else {
			struct pid_stats ns = {};
			ns.on_cpu_ns = delta;
			ns.cswitch_total = 1;
			if (ctx->prev_state == TASK_RUNNING)
				ns.cswitch_involuntary = 1;
			else
				ns.cswitch_voluntary = 1;
			bpf_map_update_elem(&pid_stats, &prev_pid, &ns, BPF_ANY);
		}
	}

	task->pid = next_pid;
	task->ts  = now;
	return 0;
}

// sched_stat_blocked: 阻塞时间 (锁等待 / I/O 同步阻塞)
SEC("tp/sched/sched_stat_blocked")
int on_sched_stat_blocked(struct trace_event_raw_sched_stat_template *ctx)
{
	__u32 pid = ctx->pid;
	if (pid == 0)
		return 0;

	struct pid_stats *s = bpf_map_lookup_elem(&pid_stats, &pid);
	if (s) {
		s->blocked_ns += ctx->delay;
	} else {
		struct pid_stats ns = {};
		ns.blocked_ns = ctx->delay;
		bpf_map_update_elem(&pid_stats, &pid, &ns, BPF_ANY);
	}
	return 0;
}

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
