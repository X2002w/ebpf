// cpu_anomaly.bpf.c — CPU 异常观测 eBPF 内核态
//
// 采集 tracepoint:
//   - sched_switch:           
//   on-CPU 时间, 上下文切换, 调度延迟
//
//   - sched_wakeup/wakeup_new: wakeup 时间戳, run queue 深度
//   - sched_stat_wait:        内核直接给出的 runqueue 等待时间
//   - sched_stat_sleep:       内核直接给出的睡眠时间
//   - sched_stat_blocked:     内核直接给出的阻塞时间（I/O 等）
//   - sched_migrate_task:     核间任务迁移
//   - sys_enter_futex/exit:   futex 等待时间
//
// 采集 perf_event (定时采样):
//   - 按固定频率抓取用户态调用栈 → 热点函数证据

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define TASK_RUNNING 0

// ─── Per‑PID 聚合统计 ────────────────────────────────────────────
struct pid_stats {
	// CPU & 上下文切换 (sched_switch)
	__u64 on_cpu_ns;  // 当前进程执行的ns数
	__u64 cswitch_total;

  // 进程切出时，状态为非running -> 主动让出cpu，锁竞争 -> sleep()...
	__u64 cswitch_voluntary;  

  // 进程切出时，状态仍然时running -> 时间片到期 or 被抢占
	__u64 cswitch_involuntary; 

	// 调度延迟 (wakeup → sched_switch, 手动计算)
	__u64 wakeup_count;
	__u64 total_sched_delay_ns;
	__u64 max_sched_delay_ns;

	// sched_stat_* tracepoint 直接给出的时间 (需要 CONFIG_SCHEDSTATS=y)
	__u64 wait_ns;             // 在 runqueue 上等待的时间
	__u64 sleep_ns;            // 睡眠时间
	__u64 blocked_ns;          // 阻塞时间（I/O 等）

	// 核间迁移
	__u64 migrate_count;

	// futex
	__u64 futex_wait_ns;       // 等待 futex 的总时间
	__u64 futex_wait_count;    // futex 等待次数
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, __u32);            // PID
	__type(value, struct pid_stats);
} pid_stats SEC(".maps");

// 记录每个cpu上当前正在运行的任务，以及切入的时间，在sched_switch时实时更新
struct cpu_task_info {
	__u32 pid;
	__u64 ts;   // 切入 CPU 的时间戳
};

// 每个cpu单独一份，无需考虑并发，用户态单独聚合所有cpu信息
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct cpu_task_info);
} cpu_task SEC(".maps");

// 调度器类型检测, linux 6.6起， 调度器默认为EEVDF
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, __u64);
} sched_class_check SEC(".maps");

// ─── Wakeup 时间戳（用于计算调度延迟） ────────────────────────────
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, __u32);    // PID
	__type(value, __u64);  // wakeup 时间戳
} wakeup_ts SEC(".maps");
// ─── Futex 等待时间戳 (类似 wakeup_ts) ────────────────────────────
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, __u32);    // PID
	__type(value, __u64);  // futex enter 时间戳
} futex_ts SEC(".maps");

// ─── 调用栈采样 ──────────────────────────────────────────────────
struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__uint(max_entries, 10240);
	__type(key, __u32);
	__type(value, __u64[127]);  // 每栈最多 127 层
} stackmap SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, __u32);    // stack_id
	__type(value, __u64);  // 采样命中次数
} stack_counts SEC(".maps");

// ─── sched_switch ─────────────────────────────────────────────────
SEC("tp/sched/sched_switch")
int on_sched_switch(struct trace_event_raw_sched_switch *ctx)
{
	__u32 prev_pid = ctx->prev_pid;
	__u32 next_pid = ctx->next_pid;

  // 获取当前ns时间戳
	__u64 now = bpf_ktime_get_ns();
	__u32 zero = 0;

  // 返回map内部value的直接指针，必须进行NULL check，否则BPF verifier 拒绝加载
	struct cpu_task_info *task = bpf_map_lookup_elem(&cpu_task, &zero);
	if (!task)
		return 0;

	// 1) 记录切出进程的 on‑CPU 时间
	if (task->pid == prev_pid && prev_pid != 0) 
  {
		__u64 delta = now - task->ts;

		struct pid_stats *s = bpf_map_lookup_elem(&pid_stats, &prev_pid);
    // 当前进程已经出现过，直接进行统计
		if (s) 
    {
			s->on_cpu_ns += delta;
			s->cswitch_total++;
			if (ctx->prev_state == TASK_RUNNING)
				s->cswitch_involuntary++;
			else
				s->cswitch_voluntary++;
		} 

    // pid 首次出现，零值初始化，只填当前事件相关的字段
    else 
    {
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

	// 2) 更新当前 CPU 任务
	task->pid = next_pid;
	task->ts  = now;

	// 4) 计算 next_pid 的调度延迟
	if (next_pid) {
		__u64 *wts = bpf_map_lookup_elem(&wakeup_ts, &next_pid);
		if (wts) {
			__u64 delay = now - *wts;
			struct pid_stats *s = bpf_map_lookup_elem(&pid_stats, &next_pid);
			if (s) {
				s->total_sched_delay_ns += delay;
				if (delay > s->max_sched_delay_ns)
					s->max_sched_delay_ns = delay;
			}
			bpf_map_delete_elem(&wakeup_ts, &next_pid);
		}
	}

	return 0;
}

// ─── sched_wakeup ─────────────────────────────────────────────────
SEC("tp/sched/sched_wakeup")
int on_sched_wakeup(struct trace_event_raw_sched_wakeup_template *ctx)
{
	__u32 pid = ctx->pid;
	if (pid == 0)
		return 0;

	__u64 now = bpf_ktime_get_ns();
	bpf_map_update_elem(&wakeup_ts, &pid, &now, BPF_ANY);

	struct pid_stats *s = bpf_map_lookup_elem(&pid_stats, &pid);
	if (s) {
		s->wakeup_count++;
	} else {
		struct pid_stats ns = {};
		ns.wakeup_count = 1;
		bpf_map_update_elem(&pid_stats, &pid, &ns, BPF_ANY);
	}

	return 0;
}

// ─── sched_wakeup_new ─────────────────────────────────────────────
SEC("tp/sched/sched_wakeup_new")
int on_sched_wakeup_new(struct trace_event_raw_sched_wakeup_template *ctx)
{
	__u32 pid = ctx->pid;
	if (pid == 0)
		return 0;

	__u64 now = bpf_ktime_get_ns();
	bpf_map_update_elem(&wakeup_ts, &pid, &now, BPF_ANY);

	struct pid_stats ns = {};
	ns.wakeup_count = 1;
	bpf_map_update_elem(&pid_stats, &pid, &ns, BPF_ANY);

	return 0;
}

// ─── sched_stat_wait: 内核直接给出的 runqueue 等待时间 ──────────────
SEC("tp/sched/sched_stat_wait")
int on_sched_stat_wait(struct trace_event_raw_sched_stat_template *ctx)
{
	__u32 pid = ctx->pid;
	if (pid == 0)
		return 0;

	struct pid_stats *s = bpf_map_lookup_elem(&pid_stats, &pid);
	if (s) {
		s->wait_ns += ctx->delay;
	} else {
		struct pid_stats ns = {};
		ns.wait_ns = ctx->delay;
		bpf_map_update_elem(&pid_stats, &pid, &ns, BPF_ANY);
	}
	return 0;
}

// ─── sched_stat_sleep: 内核直接给出的睡眠时间 ──────────────────────
SEC("tp/sched/sched_stat_sleep")
int on_sched_stat_sleep(struct trace_event_raw_sched_stat_template *ctx)
{
	__u32 pid = ctx->pid;
	if (pid == 0)
		return 0;

	struct pid_stats *s = bpf_map_lookup_elem(&pid_stats, &pid);
	if (s) {
		s->sleep_ns += ctx->delay;
	} else {
		struct pid_stats ns = {};
		ns.sleep_ns = ctx->delay;
		bpf_map_update_elem(&pid_stats, &pid, &ns, BPF_ANY);
	}
	return 0;
}

// ─── sched_stat_blocked: 内核直接给出的阻塞时间 ────────────────────
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

// ─── sched_migrate_task: 核间任务迁移 ────────────────────────────
SEC("tp/sched/sched_migrate_task")
int on_sched_migrate_task(struct trace_event_raw_sched_migrate_task *ctx)
{
	__u32 pid = ctx->pid;
	if (pid == 0)
		return 0;

	struct pid_stats *s = bpf_map_lookup_elem(&pid_stats, &pid);
	if (s) {
		s->migrate_count++;
	} else {
		struct pid_stats ns = {};
		ns.migrate_count = 1;
		bpf_map_update_elem(&pid_stats, &pid, &ns, BPF_ANY);
	}
	return 0;
}

// ─── sys_enter_futex: futex 调用入口，记录时间戳 ───────────────────
SEC("tp/syscalls/sys_enter_futex")
int on_sys_enter_futex(struct trace_event_raw_sys_enter *ctx)
{
	// futex(uaddr, op, val, ...) — 仅关注 FUTEX_WAIT (op & 0x7f == 0)
	if ((ctx->args[1] & 0x7f) != 0)
		return 0;

	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = (__u32)pid_tgid;

	__u64 now = bpf_ktime_get_ns();
	bpf_map_update_elem(&futex_ts, &pid, &now, BPF_ANY);
	return 0;
}

// ─── sys_exit_futex: futex 调用返回，结算等待时间 ───────────────────
SEC("tp/syscalls/sys_exit_futex")
int on_sys_exit_futex(struct trace_event_raw_sys_exit *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = (__u32)pid_tgid;

	__u64 *enter_ts = bpf_map_lookup_elem(&futex_ts, &pid);
	if (!enter_ts)
		return 0;

	__u64 now = bpf_ktime_get_ns();
	__u64 wait_ns = now - *enter_ts;

	struct pid_stats *s = bpf_map_lookup_elem(&pid_stats, &pid);
	if (s) {
		s->futex_wait_ns += wait_ns;
		s->futex_wait_count++;
	} else {
		struct pid_stats ns = {};
		ns.futex_wait_ns = wait_ns;
		ns.futex_wait_count = 1;
		bpf_map_update_elem(&pid_stats, &pid, &ns, BPF_ANY);
	}

	bpf_map_delete_elem(&futex_ts, &pid);
	return 0;
}

// ─── 定时栈采样 (perf_event) ─────────────────────────────────────
SEC("perf_event")
int on_profile(struct bpf_perf_event_data *ctx)
{
	__s32 stack_id = bpf_get_stackid(&ctx->regs, &stackmap, BPF_F_USER_STACK);
	if (stack_id < 0)
		return 0;

	__u64 *count = bpf_map_lookup_elem(&stack_counts, &stack_id);
	if (count) {
		__sync_fetch_and_add(count, 1);
	} else {
		__u64 one = 1;
		bpf_map_update_elem(&stack_counts, &stack_id, &one, BPF_ANY);
	}

	return 0;
}

SEC("kprobe/pick_next_task_fair")
int BPF_KPROBE(on_pick_next_fair)
{
  __u32 zero = 0;
  __u64 *cnt = bpf_map_lookup_elem(&sched_class_check, &zero);
  if(cnt)
    __sync_fetch_and_add(cnt, 1);
  return 0;
} 

