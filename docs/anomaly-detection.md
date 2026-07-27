# eebpf 异常检测方案说明

eebpf 采用 **固定阈值 + 基线自适应** 双轨异常判定机制，二者通过 OR 逻辑组合。固定阈值覆盖全部 5 个模块的所有指标，提供可靠的兜底检测；基线自适应在 SQLite 存储启用后，针对部分关键指标引入历史趋势对比，捕获"相对自身基线异常升高"的隐蔽问题。

本文档先分别介绍两种方案的工作机制与配置项，再阐述二者的组合逻辑与降级策略，最后给出部署建议。

---

## 1. 固定阈值方案

### 1.1 工作机制

固定阈值由配置文件 `eebpf.conf` 控制，未配置的项使用内置默认值。运行时逐采样窗口采集 BPF 指标，各模块的 `classify` 函数将指标与固定阈值比对，超出即触发异常。

### 1.2 配置层级

```
./eebpf.conf  >  ~/.eebpf.conf  >  /etc/eebpf.conf  >  内置默认值
   (最高)                                                   (最低)
```

三个文件均按此顺序加载，后者覆盖前者同名键。仅需写入要覆盖的项。

### 1.3 各模块阈值一览

> 默认值基于个人开发环境调校，不同机器的正常指标范围差异较大，部署后建议结合实际负载调整。

#### CPU 模块

| 配置项 | 默认值 | 说明 |
|--------|--------|------|
| `cpu_threshold` | 90 | CPU 占用异常阈值（%） |
| `cpu_profile_hz` | 99 | perf 栈采样频率（Hz） |
| `cswitch_warn_per_min` | 30000 | 上下文切换警告阈值（次/分钟） |
| `cswitch_crit_per_min` | 50000 | 上下文切换严重阈值（次/分钟） |
| `sched_delay_warn_us` | 5000 | 调度延迟警告阈值（μs） |
| `sched_delay_crit_us` | 20000 | 调度延迟严重阈值（μs） |
| `busyloop_cs_per_min` | 5000 | busy loop 判定所需最低切换数（次/分钟） |
| `stack_conc_ratio` | 0.8 | 栈集中度判定阈值（top1 占比） |

**三级分类逻辑**：

1. 先按 CPU 占用 + 切换数 + 栈集中度区分根因
2. CPU 占用 ≥ `cpu_threshold` 且切换低于 `busyloop_cs_per_min`、栈集中度 ≥ `stack_conc_ratio` → **CPU 密集**
3. 低切换 + 低栈集中度 → **busy loop**（用户态自旋）
4. 高切换 + 高调度延迟 → **锁竞争**
5. 调度延迟 ≥ `sched_delay_crit_us` → 切换风暴
6. CPU 核间迁移（runqueue 迁移率异常）→ 调度抖动

#### I/O 模块

| 配置项 | 默认值 | 说明 |
|--------|--------|------|
| `io_interval` | 3 | I/O 采样间隔（秒） |
| `min_samples_for_pct` | 100 | P99/P99.9 计算所需最少样本数 |
| `min_file_ios_for_hot` | 50 | 热点文件判定最少 I/O 次数 |

**按设备类型分级的延时阈值**（硬编码，非配置文件项）：

| 设备类型 | P99 延迟异常 | 排队等待异常 |
|----------|-------------|-------------|
| NVMe | 500 μs | 100 μs |
| SSD | 2000 μs | 500 μs |
| HDD | 10000 μs | 5000 μs |

检测维度：P99 延迟、排队等待时间、缓存失效（refault）、热点文件（单文件 I/O 集中度）、多设备同时异常。

#### 内存模块

| 配置项 | 默认值 | 说明 |
|--------|--------|------|
| `mem_interval` | 3 | 内存采样间隔（秒） |
| `mem_avail_pct` | 20 | 可用内存低水位阈值（%） |
| `mem_majfault` | 200 | 主缺页速率异常阈值（次/秒） |
| `mem_refault` | 1000 | 缓存未命中异常阈值（次/秒） |
| `mem_swapin` | 500 | swap 换入异常阈值（次/秒） |
| `mem_direct_stall_ms` | 1 | 直接回收延迟阈值（ms） |
| `mem_retry_ps` | 50 | 内存分配重试阈值（次/秒） |
| `mem_fault_ps` | 5000 | 缺页速率阈值（次/秒） |

检测维度：OOM 风险（可用内存低 + 直接回收延迟）、换页颠簸（swapin/out 激增）、缓存颠簸（refault 高）、回收抖动（重试率高）、缺页激增。

#### 锁模块

| 配置项 | 默认值 | 说明 |
|--------|--------|------|
| `lock_futex_warn_us` | 10000 | futex 等待警告阈值（μs） |
| `lock_futex_crit_us` | 50000 | futex 等待严重阈值（μs） |
| `lock_blocked_warn_ms` | 100 | 阻塞时间警告阈值（ms） |

检测逻辑：按进程（comm+pid）聚合 futex 平均等待时间，分 warn/crit 两级，叠加等待次数门槛，排除 parked 状态的误报。

#### 系统调用模块

| 配置项 | 默认值 | 说明 |
|--------|--------|------|
| `hot_freq_per_sec` | 10000 | 调用频率异常阈值（次/秒） |
| `hot_lat_us` | 10000 | 调用延迟异常阈值（μs） |
| `hot_err_rate` | 0.1 | 错误率异常阈值（0~1） |

三独立维度：频率热点、延迟热点、错误率热点。等待型系统调用（如 `epoll_wait`、`futex`）的高耗时会被识别为正常等待，不标记异常。

---

## 2. 基线自适应方案

### 2.1 设计目标

固定阈值的核心局限在于无法感知运行环境的个体差异：不同机器、不同负载下，同一指标的"正常值"可能相差一个数量级。例如 NVMe 设备在轻载时 P99 延迟约 50μs，重载时可达 300μs 但仍属正常——若固定阈值设为 500μs，轻载下突然飙升至 400μs 的真实异常将被漏报。基线自适应解决的就是这类问题：用该机器自身的历史数据建立"正常范围"，检测当前值相对于历史的异常偏离。

### 2.2 配置项

| 配置项 | 默认值 | 说明 |
|--------|--------|------|
| `storage_enabled` | 0 | SQLite 历史存储开关（基线前提） |
| `baseline_enabled` | 1 | 基线自适应总开关 |
| `baseline_min_samples` | 5 | 启用基线所需最少历史样本数 |
| `baseline_z_score` | 2.0 | z 分数（阈值 = mean + z × stddev） |
| `baseline_window_sec` | 3600 | 基线回看窗口（秒） |

### 2.3 判定流程

各模块的 `classify` 函数调用 `storage_check_baseline_anomaly(module, target, metric_key, value, fixed_threshold)`，分三步完成判定：

**Step 1 — 固定阈值判定**：直接将当前值与固定阈值对比，`fixed_hit = value > fixed_threshold`。此步不依赖任何历史数据。

**Step 2 — 基线查询**：需同时满足 `baseline_enabled`、`storage_enabled` 已开启且 `target` 参数非空三个前提。满足时调用 `storage_get_metric_baseline`，从 SQLite 的 `findings.key_metrics_json` 中按 `module + metric_key + target` 提取最近 `baseline_window_sec` 内的历史值，使用 Welford 在线算法计算历史均值 `mean` 和标准差 `stddev`。如果历史样本数 ≥ `baseline_min_samples` 且 `stddev > 0`，则计算基线阈值 `mean + baseline_z_score × stddev`，`baseline_hit = value > 基线阈值`。

**Step 3 — OR 判定**：最终 `is_anomaly = fixed_hit || baseline_hit`。同时用 `baseline_triggered = baseline_hit && !fixed_hit` 区分触发来源——仅基线命中时标记为"基线突增"，固定阈值命中时不重复标记。

### 2.4 Welford 在线算法

基线计算使用单遍 Welford 算法，避免一次性加载所有历史值到内存：

- **时间复杂度**：O(n)，n = 历史样本数
- **空间复杂度**：O(1)，仅维护 mean 和 M2 两个累加器
- **数值稳定性**：相比两步法（先算均值再算方差），Welford 能避免大数吃小数

### 2.5 各模块基线覆盖

| 模块 | 基线指标 | target 粒度 |
|------|---------|-------------|
| CPU | CPU 占用（%） | 全局（空字符串） |
| I/O | P99 延迟（μs） | 设备名（如 `sda`、`nvme0n1`） |
| 内存 | major fault 速率（次/秒） | 全局 |
| 锁 | futex 平均等待时间（μs） | 进程 `comm(pid)` |
| 系统调用 | 调用次数（次/窗口） | 全局 |

### 2.6 基线触发语义

三种判定结果：

- **固定阈值命中**（`fixed_hit = true`）：报告 subtype 按固定阈值分类逻辑输出，如"CPU 密集"、"锁竞争"、"I/O P99 延迟偏高"等。此时 `baseline_triggered` 为 false，不额外标记基线。
- **仅基线命中**（`fixed_hit = false, baseline_hit = true`）：当前值未超固定阈值但显著高于历史基线。报告 subtype 标记为"基线突增"，如"I/O 基线突增"、"锁等待基线突增"、"内存基线突增 (major fault)"，与固定阈值命中的 subtype 区分。
- **均未命中**（两者均为 false）：当前采样窗口该指标无异常。

---

## 3. 双阈值 OR 逻辑

### 3.1 核心公式

```
判定异常 = (当前值 > 固定阈值) OR (当前值 > 历史均值 + z × 历史标准差)
```

任一条件满足即报告异常。两者同时满足时，仅按固定阈值分类（不重复标记基线突增）。

### 3.2 为什么是 OR 而不是 AND

- **AND 会漏报**：若某指标长期稳定在固定阈值附近、但正常波动范围很窄，AND 会漏掉"超越历史基线但未超固定阈值"的真实异常
- **OR 更安全**：固定阈值是硬上限、基线是软检测，OR 能同时捕获"绝对过高"和"相对过高"两种情况
- **`baseline_triggered` 区分来源**：仅基线触发时 subtype 标为"基线突增"，方便人工判断是否为误报

### 3.3 基线启用前置条件

| 条件 | 结果 |
|------|------|
| `storage_enabled = 0` | 基线不工作，仅固定阈值生效 |
| `baseline_enabled = 0` | 同上 |
| 历史样本 < `baseline_min_samples` | 该指标基线不参与，仅固定阈值 |
| 历史 stddev = 0（所有历史值相同） | 基线不参与（无法计算有意义阈值） |

### 3.4 SQLite 数据不足时的降级策略

基线自适应依赖 SQLite 中积累的历史数据。以下场景下基线暂时不可用，程序自动降级为纯固定阈值模式，不报错、不中断，对用户透明：

**冷启动（首次部署）**

SQLite 数据库为空，`storage_get_metric_baseline` 返回 `count = 0`，不满足 `count ≥ baseline_min_samples`。程序仅用固定阈值判定，同时每次采样窗口自动将指标写入 `findings` 表。累积达到 `baseline_min_samples`（默认 5 次）后基线自动生效，无需重启或手动干预。

**运行中断后恢复**

若 eebpf 停止一段时间后重新启动，`baseline_window_sec`（默认 3600 秒）窗口内的历史样本可能不足。基线查询只取窗口内的记录，窗口外的旧数据被自动排除。程序以降级模式运行，新采样数据逐步填满窗口后基线恢复。

**新增 target**

例如热插拔一块新磁盘（target `nvme1n1`），该 target 无历史记录，基线对其不可用；但已有历史的 target（如 `sda`）基线不受影响。各 target 的基线独立计算，互不干扰。

**stddev 为零**

某指标所有历史值完全相同（如空闲机器 CPU 长期稳定在 0%），`stddev = 0` 导致无法计算有意义的 z-score 阈值。此时基线不参与判定，仅固定阈值生效——没有波动的指标本就不需要基线对比。

降级是静默、自动、逐指标粒度的。程序不会因基线不可用而报错或跳过检测，固定阈值始终作为兜底保障。报告中也不会出现"基线数据不足"类提示，用户只需确保 `storage_enabled` 和 `baseline_enabled` 均开启，系统会在数据就绪后自行启用基线。

---

## 4. 配置建议

### 4.1 纯固定阈值（基线关闭）

```ini
storage_enabled = 0
baseline_enabled = 0
```

适用场景：一次性诊断、无历史数据的新机器、不想引入 SQLite 依赖。

### 4.2 双阈值（推荐）

```ini
storage_enabled = 1
baseline_enabled = 1
baseline_min_samples = 5
baseline_z_score = 2.0
baseline_window_sec = 3600
```

适用场景：长期部署、持续监控，需要自适应基线对比。

### 4.3 调优建议

- **基线窗口**（`baseline_window_sec`）：默认 3600（1 小时），适合稳态负载。若负载有明显的日周期波动，可增大到 86400（24 小时），使基线覆盖完整周期。
- **z 分数**：默认 2.0（约 95% 置信）。增大可降低误报率（如 3.0 → 约 99.7%），减小可提高灵敏度。
- **最小样本数**：默认 5。新部署后需运行至少 5 次采样窗口，基线才会参与判定。
- **CPU 阈值调优**：如果有批处理任务正常跑到 95%，可将 `cpu_threshold` 调高到 98%，让基线来捕获"比平时更忙"的情况。

---
