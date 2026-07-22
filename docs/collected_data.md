# eebpf 采集数据汇总

## 1. CPU 异常检测

### 1.1 每进程指标 (`pid_stats`)

| 字段 | 类型 | 采集源 | 说明 |
|---|---|---|---|
| `on_cpu_ns` | `__u64` | `sched_switch` | 进程在 CPU 上运行的累计纳秒数 |
| `cswitch_total` | `__u64` | `sched_switch` | 上下文切换总次数（切出） |
| `cswitch_voluntary` | `__u64` | `sched_switch` | 自愿上下文切换次数（进程主动让出 CPU） |
| `cswitch_involuntary` | `__u64` | `sched_switch` | 非自愿上下文切换次数（被抢占/时间片耗尽） |
| `wakeup_count` | `__u64` | `sched_wakeup`, `sched_wakeup_new` | 被唤醒次数 |
| `total_sched_delay_ns` | `__u64` | `sched_switch`（手动计算） | 累计调度延迟（唤醒到切换入） |
| `max_sched_delay_ns` | `__u64` | `sched_switch` | 最大单次调度延迟 |
| `wait_ns` | `__u64` | `sched_stat_wait` | 在运行队列上等待的累计纳秒数（需 `CONFIG_SCHEDSTATS=y`） |
| `sleep_ns` | `__u64` | `sched_stat_sleep` | 累计睡眠纳秒数（需 `CONFIG_SCHEDSTATS=y`） |
| `blocked_ns` | `__u64` | `sched_stat_blocked` | 累计阻塞纳秒数（需 `CONFIG_SCHEDSTATS=y`） |
| `migrate_count` | `__u64` | `sched_migrate_task` | CPU 核间迁移次数 |
| `futex_wait_ns` | `__u64` | `sys_enter_futex` / `sys_exit_futex` (FUTEX_WAIT) | 累计 futex 等待纳秒数 |
| `futex_wait_count` | `__u64` | `sys_enter_futex` / `sys_exit_futex` (FUTEX_WAIT) | futex 等待次数 |
| `cpu_runtime_ns` | `__u64` | `sched_stat_runtime` | 调度器统计的 CPU 实际运行时间（需 `CONFIG_SCHEDSTATS=y`） |

### 1.2 每 CPU 状态 (`cpu_task`)

| 字段 | 类型 | 说明 |
|---|---|---|
| `pid` | `__u32` | 当前在此 CPU 上运行的进程 PID |
| `ts` | `__u64` | 切入时间戳 |

### 1.3 临时状态

| 映射表 | 键 | 值 | 用途 |
|---|---|---|---|
| `wakeup_ts` | PID | `__u64` 时间戳 | 计算调度延迟 |
| `futex_ts` | PID | `__u64` 时间戳 | 计算 futex 等待时长 |

### 1.4 调用栈采样

| 映射表 | 键 | 值 | 说明 |
|---|---|---|---|
| `stackmap` | `__u32` stack_id | `__u64[127]` IP 地址数组 | 用户态调用栈 |
| `stack_counts` | `__u32` stack_id | `__u64` 命中次数 | 每个栈的采样命中数 |

采样方式：`perf_event` 周期性采样（默认 99Hz），记录用户态调用栈。

### 1.5 调度器检测

| 数据 | 来源 | 说明 |
|---|---|---|
| `pick_next_task_fair` 调用次数 | kprobe | 确认 `fair_sched_class` 活跃 |
| 调度器类型 | 内核版本 | >= 6.6: EEVDF, < 6.6: CFS |
| 抢占模型 | `/proc/version` | 字符串解析 |
| schedstats 状态 | `/proc/sys/kernel/sched_schedstats` | 是否启用 |

### 1.6 派生指标

| 指标 | 计算方式 |
|---|---|
| CPU% | `cpu_runtime_ns / 间隔纳秒 × 100`（schedstats 启用时），否则 `on_cpu_ns / 间隔纳秒 × 100` |
| 上下文切换/分钟 | `cswitch_total / (间隔纳秒 / 60×10^9)` |
| 自愿切换/分钟 | `cswitch_voluntary / (间隔纳秒 / 60×10^9)` |
| 非自愿切换/分钟 | `cswitch_involuntary / (间隔纳秒 / 60×10^9)` |
| 自愿切换占比 | `cswitch_voluntary / cswitch_total` |
| 平均调度延迟 (us) | `wait_ns / wakeup_count / 1000`（优先），回退 `total_sched_delay_ns / wakeup_count / 1000` |
| 最大调度延迟 (us) | `max_sched_delay_ns / 1000` |
| 平均 futex 等待 (us) | `futex_wait_ns / futex_wait_count / 1000` |
| 栈集中度 | `top1 栈命中数 / 总采样数` |

### 1.7 诊断阈值与分类

| 常量 | 值 | 说明 |
|---|---|---|
| `DEFAULT_CPU_THRESHOLD` | 90.0% | CPU 异常阈值 |
| `CSWITCH_WARN_PER_MIN` | 30000 | 上下文切换告警 |
| `CSWITCH_CRIT_PER_MIN` | 50000 | 上下文切换严重 |
| `SCHED_DELAY_WARN_US` | 5000 | 调度延迟告警 |
| `SCHED_DELAY_CRIT_US` | 20000 | 调度延迟严重 |
| `BUSYLOOP_CS_PER_MIN` | 5000 | 忙等判定阈值 |
| `STACK_CONC_RATIO` | 0.8 | 栈集中度 > 80% 视为集中 |
| `VOLUNTARY_RATIO_HIGH` | 0.5 | 自愿切换占比 > 50% |

**根因分类**（优先级从高到低）：
1. CPU 高占用 (`cpu% > 90%`) → busy loop / CPU 密集计算 / 高 CPU 占用
2. 锁竞争（自愿切换 > 50% 且切换 > 30000/min）
3. 调度延迟异常
4. 上下文切换风暴 (> 50000/min)
5. 跨核迁移异常

---

## 2. I/O 异常检测

### 2.1 每块设备指标 (`dev_stats`)

| 字段 | 类型 | 采集源 | 说明 |
|---|---|---|---|
| `rd_count` | `__u64` | `block_rq_complete` | 读请求完成数 |
| `wr_count` | `__u64` | `block_rq_complete` | 写请求完成数 |
| `rd_bytes` | `__u64` | `block_rq_complete` | 读取总字节数 |
| `wr_bytes` | `__u64` | `block_rq_complete` | 写入总字节数 |
| `total_lat_ns` | `__u64` | `block_rq_complete` | 累计总延迟（插入到完成） |
| `total_qwait_ns` | `__u64` | `block_rq_complete` | 累计队列等待时间（插入到下发） |
| `total_svc_ns` | `__u64` | `block_rq_complete` | 累计服务时间（下发到完成） |
| `max_lat_ns` | `__u64` | `block_rq_complete` | 单次请求最大延迟 |
| `ii_qdepth_cur` | `__u64` | `block_rq_insert` / `block_rq_issue` | 当前插入-下发队列深度 |
| `ic_qdepth_cur` | `__u64` | `block_rq_issue` / `block_rq_complete` | 当前下发-完成队列深度 |
| `ii_qdepth_max` | `__u64` | `block_rq_insert` / `block_rq_issue` | 插入-下发队列峰值深度 |
| `ic_qdepth_max` | `__u64` | `block_rq_issue` / `block_rq_complete` | 下发-完成队列峰值深度 |
| `lat_hist[16]` | `__u64[16]` | `block_rq_complete` | 按 2 的幂次分桶的延迟直方图 (us) |
| `cache_miss_count` | `__u64` | `block_rq_insert`（仅读） | 页缓存未命中次数（500ms 内重复读同扇区） |
| `cache_miss_bytes` | `__u64` | `block_rq_insert`（仅读） | 缓存未命中涉及的总字节数 |
| `total_rd_blks` | `__u64` | `block_rq_insert`（仅读） | 窗口内总读请求块数 |

### 2.2 在途请求追踪 (`io_req`)

| 字段 | 类型 | 说明 |
|---|---|---|
| `insert_ts` | `__u64` | 请求插入时间戳 |
| `issue_ts` | `__u64` | 请求下发到设备时间戳 |
| `dev` | `dev_t` | 设备号 |
| `nr_sector` | `unsigned int` | 扇区数 |
| `rw` | `__u8` | 1=写, 0=读 |

### 2.3 缓存颠簸检测 (`block_read_hist`)

| 字段 | 类型 | 说明 |
|---|---|---|
| 键: `dev` | `__u32` | 设备号 |
| 键: `sector` | `__u64` | 扇区号 |
| 值: `first_ts` | `__u64` | 第一次读时间戳 |
| 值: `last_ts` | `__u64` | 最近一次读时间戳 |
| 值: `read_count` | `__u32` | 窗口内重复读次数 |

缓存窗口：500ms（`CACHE_WINDOW_NS = 500000000`）

### 2.4 派生指标

| 指标 | 计算方式 |
|---|---|
| 总 IOPS | `(rd_count + wr_count) / 间隔秒` |
| 读吞吐 MB/s | `rd_bytes / 间隔秒 / 10^6` |
| 写吞吐 MB/s | `wr_bytes / 间隔秒 / 10^6` |
| 平均总延迟 (us) | `total_lat_ns / 总IO数 / 1000` |
| 平均队列等待 (us) | `total_qwait_ns / 总IO数 / 1000` |
| 平均服务时间 (us) | `total_svc_ns / 总IO数 / 1000` |
| 最大延迟 (us) | `max_lat_ns / 1000` |
| P99 延迟 (us) | 从 `lat_hist` 计算 |
| P99.9 延迟 (us) | 从 `lat_hist` 计算 |
| 缓存命中率 (%) | `100 - (cache_miss_count / total_rd_blks × 100)` |
| 队列深度使用率 (%) | `ic_qdepth_max / 内核 nr_requests × 100` |

### 2.5 诊断阈值

| 磁盘类型 | P99 延迟阈值 | 队列等待阈值 |
|---|---|---|
| NVMe | 500 us | 100 us |
| SSD | 2000 us | 500 us |
| HDD | 10000 us | 5000 us |
| 未知 | 5000 us | 2000 us |

磁盘类型通过 `/sys/block/*/queue/rotational` 判定。

**触发条件**（需 `MIN_SAMPLES_FOR_PCT = 100` 样本）：
- `flag_lat`: P99 延迟超过磁盘类型阈值
- `flag_qd`: 队列深度使用率 > 70%
- `flag_qwait`: 平均队列等待超过阈值 且 占延迟比 > 30%
- `flag_cache`: 缓存未命中率 > 10% 且 读块数 > 100
- `flag_hot`: Top-3 文件 IOPS > 总文件 I/O 70% 且 总文件 I/O >= 50

---

## 3. 内存异常检测

### 3.1 每进程指标 (`pid_mem`)

| 字段 | 类型 | 采集源 | 说明 |
|---|---|---|---|
| `fault_raw` | `__u64` | `kretprobe/handle_mm_fault` | `handle_mm_fault` 调用总次数（含重试） |
| `fault_completed` | `__u64` | `kretprobe/handle_mm_fault` | 非 VMF_RETRY/VMF_ERROR 的完成次数 |
| `direct_reclaim_cnt` | `__u64` | `on_direct_reclaim_end` | 直接回收次数 |
| `direct_reclaim_ns` | `__u64` | `on_direct_reclaim_end` | 累计直接回收耗时纳秒数 |
| `reclaimed_pages` | `__u64` | `on_direct_reclaim_end` | 回收的页面数 |

### 3.2 全局指标 (`global_mem`)

| 字段 | 类型 | 采集源 | 说明 |
|---|---|---|---|
| `kswapd_wake_count` | `__u64` | `mm_vmscan_kswapd_wake` | kswapd 唤醒次数 |
| `kswapd_active_ns` | `__u64` | `mm_vmscan_kswapd_wake` / `mm_vmscan_kswapd_sleep` | kswapd 活跃累计纳秒数 |
| `direct_reclaim_cnt` | `__u64` | `mm_vmscan_direct_reclaim_begin` | 系统级直接回收次数 |
| `direct_reclaim_ns` | `__u64` | `mm_vmscan_direct_reclaim_end` | 系统级累计直接回收耗时 |
| `reclaimed_pages` | `__u64` | `on_direct_reclaim_end` | 系统级回收页面总数 |
| `page_scan` | `__u64` | `mm_vmscan_lru_shrink_inactive` | LRU 扫描页面数 |
| `page_steal` | `__u64` | `mm_vmscan_lru_shrink_inactive` | LRU 实际回收页面数 |
| `oom_kills` | `__u64` | `oom/mark_victim` | OOM 杀死次数 |
| `last_oom_pid` | `__u32` | `oom/mark_victim` | 最近 OOM 受害进程 PID |

### 3.3 /proc/meminfo 采集

| 字段 | 类型 | proc 项 | 说明 |
|---|---|---|---|
| `total` | `unsigned long long` | MemTotal | 总内存 (kB) |
| `free` | `unsigned long long` | MemFree | 空闲内存 (kB) |
| `available` | `unsigned long long` | MemAvailable | 可用内存 (kB)，不存在则按 free+buffers+cached+sreclaimable 计算 |
| `buffers` | `unsigned long long` | Buffers | 缓冲区 (kB) |
| `cached` | `unsigned long long` | Cached | 页缓存 (kB) |
| `swaptotal` | `unsigned long long` | SwapTotal | 交换区总大小 (kB) |
| `swapfree` | `unsigned long long` | SwapFree | 交换区空闲 (kB) |
| `dirty` | `unsigned long long` | Dirty | 脏页 (kB) |
| `writeback` | `unsigned long long` | Writeback | 回写中页面 (kB) |
| `anon` | `unsigned long long` | AnonPages | 匿名页 (kB) |
| `sreclaimable` | `unsigned long long` | SReclaimable | 可回收 slab (kB) |
| `shmem` | `unsigned long long` | Shmem | 共享内存 (kB) |
| `mapped` | `unsigned long long` | Mapped | 映射文件页 (kB) |

### 3.4 /proc/vmstat 采集

| 字段 | 类型 | proc 项 | 说明 |
|---|---|---|---|
| `pgfault` | `unsigned long long` | pgfault | 页面错误总次数（含 minor + major） |
| `pgmajfault` | `unsigned long long` | pgmajfault | 主页面错误次数 |
| `pswpin` | `unsigned long long` | pswpin | 换入页面数 |
| `pswpout` | `unsigned long long` | pswpout | 换出页面数 |
| `ws_refault` | `unsigned long long` | workingset_refault | 工作集重故障（总） |
| `ws_refault_anon` | `unsigned long long` | workingset_refault_anon | 工作集重故障（匿名） |
| `ws_refault_file` | `unsigned long long` | workingset_refault_file | 工作集重故障（文件） |
| `pgscan_direct` | `unsigned long long` | pgscan_direct | 直接回收扫描页数 |
| `pgscan_kswapd` | `unsigned long long` | pgscan_kswapd | kswapd 扫描页数 |
| `oom_kill` | `unsigned long long` | oom_kill | OOM 杀死次数 |

### 3.5 /proc/[pid]/stat 采集

| 数据 | 来源字段 | 说明 |
|---|---|---|
| minflt | 字段 10 | 进程 minor page fault 累计 |
| majflt | 字段 12 | 进程 major page fault 累计 |

缓存上轮值，计算窗口增量。

### 3.6 派生速率指标 (`win_rates`)

| 指标 | 计算方式 |
|---|---|
| `pgfault_ps` | `delta_pgfault / 间隔秒` |
| `pgmajfault_ps` | `delta_pgmajfault / 间隔秒` |
| `pswpin_ps` | `delta_pswpin / 间隔秒` |
| `pswpout_ps` | `delta_pswpout / 间隔秒` |
| `refault_ps` | `delta_refault / 间隔秒`（优先 `ws_refault_anon + ws_refault_file`，回退 `ws_refault`） |
| `pgscan_direct_ps` | `delta_pgscan_direct / 间隔秒` |
| `oom_delta` | 绝对增量（非速率） |

### 3.7 诊断阈值与分类

| 常量 | 值 | 说明 |
|---|---|---|
| `DEF_AVAIL_PCT_LO` | 10.0% | 可用内存低水位 |
| `DEF_MAJFAULT_HI` | 200.0/s | 主页面错误阈值 |
| `DEF_REFAULT_HI` | 1000.0/s | 工作集重故障阈值 |
| `DEF_SWAPIN_HI` | 500.0/s | 换入/换出阈值 |
| `DIRECT_STALL_HI_MS` | 1.0 ms | 直接回收平均停顿阈值 |
| `RETRY_HI_PS` | 50.0/s | 页面错误重试阈值 |
| `FAULT_HI_PS` | 5000.0/s | 总页面错误阈值 |
| `CONSIST_TOL_PCT` | 15.0% | eBPF 与 /proc 一致性容差 |

**触发条件**：
- `flag_lowmem`: 可用内存 < 10%
- `flag_major`: 主页面错误 > 200/s
- `flag_swap`: 换入/出 > 500/s 且 swap 使用 > 0
- `flag_refault`: 工作集重故障 > 1000/s
- `flag_direct`: 直接回收 > 0 且 平均停顿 > 1ms
- `flag_oom`: OOM 增量 > 0
- `flag_retry`: 重试 > 50/s
- `flag_fault`: 页面错误 > 5000/s

**根因分类**：OOM → 交换颠簸 → 缓存颠簸 → 直接回收颠簸 → 主页面错误激增 → 页面错误重试 → 高内存占用

---

## 4. 锁竞争检测

### 4.1 每个锁的 futex 指标 (`futex_key_stats`)

键：`(tgid, uaddr)` — 线程组 ID + futex 用户态地址

| 字段 | 类型 | 说明 |
|---|---|---|
| `wait_ns` | `__u64` | 累计等待纳秒数 |
| `wait_count` | `__u64` | 等待次数 |
| `max_wait_ns` | `__u64` | 单次最大等待纳秒数 |

### 4.2 每线程锁指标 (`lock_pid_stats`)

| 字段 | 类型 | 说明 |
|---|---|---|
| `futex_wait_ns` | `__u64` | 累计 futex 等待纳秒数 |
| `futex_wait_count` | `__u64` | futex 等待次数 |
| `futex_max_wait_ns` | `__u64` | 单次最大 futex 等待 |

### 4.3 临时状态

| 映射表 | 键 | 值 | 用途 |
|---|---|---|---|
| `lock_futex_ts` | TID | `{ ts: u64, uaddr: u64 }` | 记录 futex 进入时间戳和等待地址 |

### 4.4 调用栈 (`lock_stackmap`, `lock_stack_counts`)

记录 futex 等待点的用户态调用栈。

### 4.5 复用 CPU 模块数据

锁模块同时加载 CPU skeleton，复用 `pid_stats` 中的 `on_cpu_ns`, `cswitch_total`, `cswitch_voluntary`, `blocked_ns`。

### 4.6 派生指标

| 指标 | 计算方式 |
|---|---|
| 全局平均 futex 等待 (us) | `总 futex 纳秒 / 总 futex 等待次数 / 1000` |
| 每线程平均 futex 等待 (us) | `futex_wait_ns / futex_wait_count / 1000` |
| 每线程最大 futex 等待 (us) | `futex_max_wait_ns / 1000` |
| 每锁平均等待 (us) | `wait_ns / wait_count / 1000` |
| 每锁最大等待 (us) | `max_wait_ns / 1000` |
| 热门锁集中度 | `top1 锁总等待 / 全局 futex 等待` |

### 4.7 诊断阈值与分类

| 常量 | 值 | 说明 |
|---|---|---|
| `FUTEX_WARN_US` | 10000 us (10ms) | 平均 futex 等待告警 |
| `FUTEX_CRIT_US` | 50000 us (50ms) | 平均 futex 等待严重 |
| `HOT_KEY_RATIO` | 0.5 (50%) | 单锁集中度 |
| `VOLUNTARY_RATIO_HIGH` | 0.5 (50%) | 自愿切换占比高 |
| `BLOCKED_WARN_MS` | 100 ms | 阻塞时间告警 |

**非竞争 futex 排除**：`wait_count <= 3` 且 `avg > 50ms` 且 `cswitch < 5000/min` → 视为"停放"线程，非锁竞争。

**根因分类**：
1. 锁竞争（临界区过大）：wait_count > 5 且 avg > 50ms
2. 锁竞争（热点锁集中）：同 TGID 内 >= 2 把热锁，top1 > 50%
3. 锁竞争（粗粒度锁）：自愿切换 > 50%，切换 > 10000/min，futex > 3
4. 通用锁竞争：wait_count > 3 且 avg > 10ms

---

## 5. 系统调用热点分析

### 5.1 每系统调用指标 (`sys_stats`)

键：系统调用号

| 字段 | 类型 | 采集源 | 说明 |
|---|---|---|---|
| `count` | `__u64` | `raw_syscalls/sys_enter` / `sys_exit` | 调用次数（含 EAGAIN/EINTR/EINPROGRESS，不含于 err_count） |
| `total_ns` | `__u64` | `raw_syscalls/sys_enter` / `sys_exit` | 累计耗时纳秒数 |
| `max_ns` | `__u64` | `raw_syscalls/sys_enter` / `sys_exit` | 单次最大耗时 |
| `err_count` | `__u64` | `raw_syscalls/sys_enter` / `sys_exit` | 错误返回次数（排除 -EAGAIN/-EINTR/-EINPROGRESS） |

### 5.2 每线程每系统调用指标 (`pid_nr_stats`)

键：`(tid << 32) | nr`

| 字段 | 类型 | 说明 |
|---|---|---|
| `count` | `__u64` | 此线程此系统调用的调用次数 |
| `total_ns` | `__u64` | 累计耗时 |
| `max_ns` | `__u64` | 单次最大耗时 |

### 5.3 临时状态

| 映射表 | 键 | 值 | 用途 |
|---|---|---|---|
| `sys_enter_ts` | TID | `{ enter_ts: u64, nr: u32 }` | 记录系统调用进入时间戳和调用号 |

### 5.4 派生指标

| 指标 | 计算方式 |
|---|---|
| 每秒调用率 | `count / 间隔秒` |
| 平均延迟 (us) | `total_ns / count / 1000` |
| 最大延迟 (ms) | `max_ns / 10^6` |
| 错误率 (%) | `err_count / count × 100` |
| 每线程总调用率 | `总 count / 间隔秒` |
| 每线程平均延迟 | `总 total_ns / 总 count / 1000` |
| 每线程最高频调用 | 按 count 排序 top1 |
| 每线程最耗时调用 | 按 total_ns 排序 top1 |

### 5.5 等待型系统调用

以下系统调用的高延迟视为正常等待行为，不标记异常：

`poll`, `select`, `epoll_wait`, `nanosleep`, `clock_nanosleep`, `pselect6`, `ppoll`, `epoll_pwait`, `epoll_pwait2`

### 5.6 诊断阈值

| 常量 | 值 | 说明 |
|---|---|---|
| `FREQ_WARN_PER_SEC` | 10000/s | 调用频率告警 |
| `LAT_WARN_US` | 10000 us (10ms) | 平均延迟告警 |
| `ERR_RATE_WARN` | 0.1 (10%) | 错误率告警 |

**每条系统调用的诊断**：
- 频率 > 10k/s 且 延迟 > 10ms → "高频+高延迟"
- 频率 > 10k/s → "高频调用"
- 延迟 > 10ms → "高延迟调用"
- 错误率 > 10% → "高错误率"

---

## 6. 热点文件检测

### 6.1 每文件指标 (`file_stats`)

键：`(dev << 32) | ino`

| 字段 | 类型 | 采集源 | 说明 |
|---|---|---|---|
| `rd_count` | `__u64` | `fexit/vfs_read` | 成功读调用次数（ret > 0） |
| `wr_count` | `__u64` | `fexit/vfs_write` | 成功写调用次数（ret > 0） |
| `rd_bytes` | `__u64` | `fexit/vfs_read` | 读取总字节数 |
| `wr_bytes` | `__u64` | `fexit/vfs_write` | 写入总字节数 |
| `total_lat_ns` | `__u64` | `fexit/vfs_read` / `fexit/vfs_write` | 累计 VFS 层延迟 |
| `last_ts` | `__u64` | `fexit/vfs_read` / `fexit/vfs_write` | 最近访问时间戳 |
| `comm[16]` | `char[16]` | 首次访问时 `bpf_get_current_comm` | 首次访问进程名 |
| `fname[40]` | `char[40]` | `BPF_CORE_READ(f_path.dentry.d_name.name)` | 文件名 |

伪文件系统（device major == 0，如 eventfd, pipe, socket）已过滤。

### 6.2 在途 VFS 调用追踪 (`vfs_pending`)

键：`{ tid, __pad, file_addr }`

| 值字段 | 类型 | 说明 |
|---|---|---|
| `ts` | `__u64` | 入口时间戳 |
| `file_key` | `__u64` | 计算的 `(dev << 32) \| ino` |

### 6.3 派生指标

| 指标 | 计算方式 |
|---|---|
| 文件 IOPS | `(rd_count + wr_count) / 间隔秒` |
| 读吞吐 MB/s | `rd_bytes / 间隔秒 / 10^6` |
| 写吞吐 MB/s | `wr_bytes / 间隔秒 / 10^6` |
| 平均延迟 (us) | `total_lat_ns / (rd_count + wr_count) / 1000` |
| Top-3 IOPS 集中度 (%) | `top3 IOPS 合计 / 总文件 IOPS × 100` |

### 6.4 热点分类

- Top-3 > 70% → "热点文件访问集中"
- Top-3 > 50% → "存在一定热点集中"
- Top-3 <= 50% → "分布均匀，无明显热点"

---

## 7. 系统概览信息

### 7.1 系统负载 (`sys_metrics`)

| 字段 | 类型 | 来源 | 说明 |
|---|---|---|---|
| `load1` | `double` | `/proc/loadavg` | 1 分钟平均负载 |
| `load5` | `double` | `/proc/loadavg` | 5 分钟平均负载 |
| `load15` | `double` | `/proc/loadavg` | 15 分钟平均负载 |
| `procs_running` | `int` | `/proc/loadavg` | 运行/就绪进程数 |
| `procs_blocked` | `int` | `/proc/loadavg` | 阻塞进程数 |

### 7.2 系统信息

| 信息 | 来源 | 说明 |
|---|---|---|
| CPU 核心数 | `sysconf(_SC_NPROCESSORS_ONLN)` | 在线 CPU 数 |
| 活跃进程数 | 遍历 `/proc` | 有 stat 文件的进程数 |
| 调度器类型 | 内核版本 >= 6.6 → EEVDF, 否则 CFS | — |
| 抢占模型 | `/proc/version` 字符串解析 | — |
| schedstats 状态 | `/proc/sys/kernel/sched_schedstats` | — |

---

## 8. 采集方式汇总

| 模块 | 采集方式 | 采集目标 |
|---|---|---|
| CPU | tracepoint `sched_switch`, `sched_wakeup`, `sched_wakeup_new`, `sched_stat_*`, `sched_migrate_task`; tracepoint `sys_enter_futex`/`sys_exit_futex`; perf_event 采样 | 每进程调度指标、futex 等待、调用栈 |
| I/O | tracepoint `block_rq_insert`, `block_rq_issue`, `block_rq_complete` | 每块设备 I/O 指标、队列深度、延迟直方图、缓存命中 |
| I/O (文件) | fentry/fexit `vfs_read`, `vfs_write` | 每文件 VFS 层 I/O 指标 |
| 内存 | kretprobe `handle_mm_fault`; tracepoint `mm_vmscan_*`, `oom/mark_victim`; `/proc/meminfo`, `/proc/vmstat`, `/proc/[pid]/stat` | 页面错误、直接回收、kswapd、OOM、系统内存状态 |
| 锁 | tracepoint `sys_enter_futex`/`sys_exit_futex` (FUTEX_WAIT); 复用 CPU skeleton | 每锁/每线程 futex 等待、调用栈、上下文切换 |
| 系统调用 | tracepoint `raw_syscalls/sys_enter`, `raw_syscalls/sys_exit` | 每系统调用/每线程的 count、延迟、错误率 |
