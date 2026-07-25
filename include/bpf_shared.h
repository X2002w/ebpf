#ifndef BPF_SHARED_H
#define BPF_SHARED_H

// bpf_shared.h — BPF 内核态与用户态共享的结构体定义
//
// 仅包含 BPF map 的 key/value 结构, 消除 .bpf.c 与 .c 之间的手工复制
// BPF 侧: 先 #include "vmlinux.h" (提供 __u8/__u32/__u64/dev_t), 再 include 本头
// 用户态: 先 #include <linux/types.h> + <sys/types.h>, 再 include 本头
//
// 字段顺序与类型必须与 BPF 侧保持一致, 改动时务必同步两端

#define HIST_SLOTS 16  // I/O 延迟直方图桶数

// CPU 模块

// Per-PID 聚合统计 (pid_stats map 的 value)
struct pid_stats {
	__u64 on_cpu_ns;             // 当前进程执行的ns数
	__u64 cswitch_total;
	__u64 cswitch_voluntary;     // 进程切出时状态非running -> 主动让出cpu
	__u64 cswitch_involuntary;   // 进程切出时状态仍为running -> 时间片到期或被抢占
	__u64 wakeup_count;
	__u64 total_sched_delay_ns;  // wakeup → sched_switch 手动计算的调度延迟
	__u64 max_sched_delay_ns;
	__u64 wait_ns;               // sched_stat_wait: runqueue 等待时间
	__u64 sleep_ns;              // sched_stat_sleep: 睡眠时间
	__u64 blocked_ns;            // sched_stat_blocked: 阻塞时间(I/O 等)
	__u64 migrate_count;         // 核间任务迁移
	__u64 futex_wait_ns;
	__u64 futex_wait_count;
	__u64 cpu_runtime_ns;        // sched_stat_runtime: 内核核算的实际执行时间
};

// 每个 CPU 当前正在运行的任务 (cpu_task PERCPU_ARRAY 的 value)
struct cpu_task_info {
	__u32 pid;
	__u64 ts;   // 切入 CPU 的时间戳
};

// I/O 模块

// 每个块设备单独的检测数据 (dev_stats map 的 value)
struct dev_stats {
	__u64 rd_count;
	__u64 wr_count;
	__u64 rd_bytes;
	__u64 wr_bytes;
	__u64 total_lat_ns;
	__u64 total_qwait_ns;
	__u64 total_svc_ns;
	__u64 max_lat_ns;
	__u64 ii_qdepth_cur;         // insert->issue 队列深度
	__u64 ic_qdepth_cur;         // issue->complete 队列深度
	__u64 ii_qdepth_max;
	__u64 ic_qdepth_max;
	__u64 lat_hist[HIST_SLOTS];  // 延迟直方图, bucket[i]=[2^i, 2^(i+1)) us
	__u64 cache_miss_count;      // 窗口内重复读事件数
	__u64 cache_miss_bytes;
	__u64 total_rd_blks;         // 窗口内读块总数
};

// 缓存失效检测: 块设备扇区最近读记录 (block_read_hist map 的 key/value)
struct block_read_key {
	__u32 dev;
	__u64 sector;
};

struct block_read_val {
	__u64 first_ts;
	__u64 last_ts;
	__u32 read_count;
};

// 单次 IO request (io_req map 的 value)
struct io_req_info {
	__u64 insert_ts;
	__u64 issue_ts;
	dev_t dev;
	__u32 nr_sector;
	__u8 rw;                     // 0=读, 1=写
};

// Lock 模块

// Per-futex-key 热点锁统计 (futex_key_stats map 的 key/value)
struct lock_futex_key {
	__u32 tgid;
	__u64 uaddr;
};

struct futex_hot_stats {
	__u64 wait_ns;
	__u64 wait_count;
	__u64 max_wait_ns;
};

// Per-PID futex 聚合 (lock_pid_stats map 的 value)
struct lock_pid_stats {
	__u64 futex_wait_ns;
	__u64 futex_wait_count;
	__u64 futex_max_wait_ns;
};

// Futex 等待跟踪 (lock_futex_ts map 的 value)
struct futex_wait_val {
	__u64 ts;
	__u64 uaddr;
};

// Mem 模块

// Per-PID 内存统计 (pid_mem map 的 value)
struct pid_mem_stats {
	__u64 fault_raw;             // handle_mm_fault 调用次数
	__u64 fault_completed;       // 缺页处理完成次数
	__u64 direct_reclaim_cnt;
	__u64 direct_reclaim_ns;
	__u64 reclaimed_pages;
	__u64 fault_count;
	__u64 last_fault_ts;
};

// 全局内存统计 (global_mem ARRAY 的 value)
struct global_mem_stats {
	__u64 kswapd_wake_count;
	__u64 kswapd_active_ns;
	__u64 direct_reclaim_cnt;
	__u64 direct_reclaim_ns;
	__u64 reclaimed_pages;
	__u64 page_scan;             // inactive lru 扫描页数
	__u64 page_steal;            // inactive lru 回收页数
	__u64 oom_kills;
	__u32 last_oom_pid;
};

#endif // BPF_SHARED_H
