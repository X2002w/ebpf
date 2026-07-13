// mem_anomaly.bpf.c - mem 异常检测 kernel 态

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MAP_ANONYMOUS 0x20

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// 记录每个进程的缺页此次数
struct pid_mem_stats {

  __u64 anon_mmap_count;
  __u64 anon_mmap_bytes;
  __u64 file_mmap_count;
  __u64 file_mmap_bytes;

  __u64 direct_reclaim_cnt;
  __u64 direct_reclaim_ns;
  __u64 reclaimed_pages;

  __u64 fault_count;
  __u64 last_fault_ts;  // 最近一次缺页时间戳
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 10240);
  __type(key, __u32);
  __type(value, struct pid_mem_stats);
} pid_mem SEC(".maps");

struct global_mem_stats {

  // kswapd -> kernel 专门负责在内存不足时执行回收物理内存 (RAM) 的线程
  __u64 kswapd_wake_count;
  __u64 kswapd_active_ns;
  __u64 direct_reclaim_cnt;
  __u64 direct_reclaim_ns;
  __u64 reclaimed_pages;
};

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct global_mem_stats);
} global_mem SEC(".maps");

// kswapd 线程执行时间戳
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, __u64);
} kswapd_ts SEC(".maps");

// 直接回收时间戳 key -> pid
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 10240);
  __type(key, __u32);
  __type(value, __u64);
} reclaim_ts SEC(".maps");

// 获取pid_mem_stats
static inline struct pid_mem_stats *get_pid_stats(__u32 pid)
{
  struct pid_mem_stats *p = bpf_map_lookup_elem(&pid_mem, &pid);
  if (!p) {
    struct pid_mem_stats zero = {};
    bpf_map_update_elem(&pid_mem, &pid, &zero, BPF_ANY);
    p = bpf_map_lookup_elem(&pid_mem, &pid);
    if (!p) return 0;
  }
  return p;
}

// 获取global_mem_stats
static inline struct global_mem_stats *get_global_stats(void)
{
  __u32 zero = 0;
  struct global_mem_stats *g = bpf_map_lookup_elem(&global_mem, &zero);
  if (!g) {
    struct global_mem_stats gzero = {};
    bpf_map_update_elem(&global_mem, &zero, &gzero, BPF_ANY);
    g = bpf_map_lookup_elem(&global_mem, &zero);
    if (!g) return 0;
  }
  return g;
}


// 统计kswapd 线程
SEC("tp/vmscan/mm_vmscan_kswapd_wake")
int on_kswapd_wake(struct trace_event_raw_mm_vmscan_kswapd_wake *ctx)
{
  __u64 now = bpf_ktime_get_ns();
  __u32 zero = 0;
  struct global_mem_stats *g = get_global_stats();

  if (g) {
    __sync_fetch_and_add(&g->kswapd_wake_count, 1);
  }

  // 记录时间戳，计算活跃时间
  bpf_map_update_elem(&kswapd_ts, &zero, &now, BPF_ANY);
  return 0;
}

SEC("tp/vmscan/mm_vmscan_kswapd_sleep")
int on_kswapd_sleep(struct trace_event_raw_mm_vmscan_kswapd_sleep *ctx)
{
  __u64 now = bpf_ktime_get_ns();
  __u32 zero = 0;

  __u64 *wake_ts = bpf_map_lookup_elem(&kswapd_ts, &zero);
  if (!wake_ts)
    return 0;

  __u64 active_ns = now - *wake_ts;

  struct global_mem_stats *g = get_global_stats();
  if (g) {
    __sync_fetch_and_add(&g->kswapd_active_ns, active_ns);
  }

  return 0;
}

SEC("tp/vmscan/mm_vmscan_direct_reclaim_begin")
int on_direct_reclaim_begin(struct trace_event_raw_mm_vmscan_direct_reclaim_begin_template *ctx)
{
  __u32 pid = bpf_get_current_pid_tgid() >> 32;
  __u64 now = bpf_ktime_get_ns();

  bpf_map_update_elem(&reclaim_ts, &pid, &now, BPF_ANY);

  struct global_mem_stats *g = get_global_stats();
  if (g) {
    __sync_fetch_and_add(&g->direct_reclaim_cnt, 1);
  }

  return 0;
}

SEC("tp/vmscan/mm_vmscan_direct_reclaim_end")
int on_direct_reclaim_end(struct trace_event_raw_mm_vmscan_direct_reclaim_end_template *ctx)
{
  __u32 pid = bpf_get_current_pid_tgid() >> 32;
  __u64 now = bpf_ktime_get_ns();
  __u64 nr_reclaimed = ctx->nr_reclaimed;
  
  __u64 *start_ts = bpf_map_lookup_elem(&reclaim_ts, &pid);
  if (start_ts) {

    __u64 reclaim_ns = now - *start_ts;
    struct pid_mem_stats *g = get_pid_stats(pid);
    if (g) {
      __sync_fetch_and_add(&g->direct_reclaim_cnt, 1);
      __sync_fetch_and_add(&g->direct_reclaim_ns, reclaim_ns);
      __sync_fetch_and_add(&g->reclaimed_pages, nr_reclaimed);
    }

    bpf_map_delete_elem(&reclaim_ts, &pid);
  }
  struct global_mem_stats *g = get_global_stats();
  if (g) {
    __sync_fetch_and_add(&g->reclaimed_pages, nr_reclaimed);
  }
  return 0;
}


/*
SEC("tp/expections/page_fault_user")
int on_page_fault_user(void *ctx)
{
  __u32 pid = btf_bpf_get_current_pid_tgid() >> 32;

  struct pid_mem_stats *p = bpf_map_lookup_elem(&pid_faults, &pid);
  if (!p) {
    struct pid_mem_stats zero = {};
    bpf_map_update_elem(&pid_faults, &pid);
    p = bpf_map_lookup_elem(&pid_faults, &pid);
    if (!p) return 0;
  }

  // 查看当前是否缺页
   p->last_fault_ts = bpf_ktime_get_ns();
  return 0;
}

SEC("tp/syscalls/sys_enter_mmap")
int on_sys_enter_mmap(struct trace_event_raw_sys_enter *ctx)
{
  // mmap 系统调用参数:
  // args[0] -> addr, 1 -> len, prot(保护标志), flags, fd, offset
  __u32 pid = bpf_get_current_pid_tgid() >> 32;

  long unsigned int addr = ctx->args[0];
  long unsigned int len = ctx->args[1];
  long unsigned int prot = ctx->args[2];
  long unsigned int flags = ctx->args[3];
  


  return 0;
}

*/
