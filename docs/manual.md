# eebpf 用户手册

eebpf 是基于 eBPF (libbpf + CO-RE) 的轻量级系统异常观测与根因定位工具，覆盖 CPU、I/O、内存、锁竞争、系统调用热点 5 类异常场景，输出结构化诊断报告。

---

## 1. 安装说明

### 1.1 运行环境要求

- 操作系统: openKylin, debian (或其他主流 Linux 发行版亦可)
- 内核版本: 6.6+，需开启 `CONFIG_DEBUG_INFO_BTF`（存在 `/sys/kernel/btf/vmlinux`）
- 硬件架构: x86_64 / ARM64（CI 测试），系统调用名映射通过 `__NR_*` 宏编译期适配架构
- 运行权限: root (加载 BPF 程序、perf 采样均需要特权)

### 1.2 源码构建依赖

- clang(19+)（编译用户态代码与 BPF 字节码）
- libbpf 开发库（链接 `-lbpf -lelf -lz`）
- bpftool（生成 vmlinux.h 与 skeleton 头文件）
- make

### 1.3 本机构建

- 拉取仓库代码(git clone git@github.com:X2002w/ebpf.git)
- 在项目根目录执行下述命令

```bash
make clean    # 清理构建产物
make          # 生成 ./eebpf
```

构建流程自动完成：从内核 BTF 导出 `build/vmlinux.h` -> 编译 `src/*.bpf.c` 为 BPF 目标文件 -> bpftool 生成 skeleton -> 编译链接用户态程序。

若报错 `Kernel BTF not found`，说明内核未开启 BTF，无法使用 CO-RE，需更换内核或发行版。

### 1.4 容器化构建（openKylin 环境）

```bash
./enter-container.sh   # 构建镜像、启动容器并进入 /workspace
make                   # 容器内构建
```

容器由 docker-compose 管理，已挂载宿主机必要目录；运行 BPF 程序需要特权容器。CI（GitHub Actions）会自动构建并发布最新构建/测试镜像。

---

## 2. 使用说明

统一入口，按子命令分发：

```bash
sudo ./eebpf <子命令> [选项]
```

| 子命令 | 功能 |
|---|---|
| `cpu` | CPU 异常检测（占用、调度延迟、上下文切换，三类根因：CPU 密集 / busy loop / 锁竞争） |
| `io` | I/O 异常检测（块设备吞吐、延迟、队列深度、缓存失效、热点文件） |
| `mem` | 内存异常检测（缺页洪流、直接回收、kswapd、OOM，并与 /proc 数据对账） |
| `lock` | 锁竞争检测（futex 等待追踪、热点锁识别、等待栈分析） |
| `hot` | 系统调用热点分析（高频、高耗时、高错误率系统调用及进程级诊断） |

全局选项：`-v, --version` 显示版本；`-h, --help` 显示帮助。

### 常用示例

```bash
sudo ./eebpf cpu                          # 默认参数持续观测 CPU
sudo ./eebpf cpu -i 3 -d 60               # 每 3 秒采样，运行 60 秒
sudo ./eebpf cpu -p 99 -o /tmp/report.txt # 启用 99Hz 栈采样并输出到文件
sudo ./eebpf cpu -j --schedstats          # 额外输出 report.json，开启调度器统计
sudo ./eebpf mem -a 15 -f 100             # 更敏感的内存阈值
sudo ./eebpf lock -d 180                  # 观测 180 秒锁竞争
```

配合压测工具复现异常：

```bash
stress-ng --mutex 8 --timeout 180s &   # 复现锁竞争
sudo ./eebpf lock -d 180
```

诊断报告默认输出到标准输出；Markdown 报告写入 `report/` 目录。

---

## 3. 参数说明

所有子命令的短参数均有对应长参数，公共参数命名统一。

### 3.1 公共参数

| 参数 | 说明 |
|---|---|
| `-i, --interval <秒>` | 采样间隔，必须 >= 1 |
| `-d, --duration <秒>` | 总运行时长，0 表示持续运行直到 Ctrl-C（默认: 0） |
| `-o, --output <文件路径>` | 输出到文件（默认: 标准输出，`io`/`mem` 暂不支持） |
| `-h, --help` | 显示帮助信息 |

### 3.2 cpu

| 参数 | 默认 | 说明 |
|---|---|---|
| `-i, --interval <秒>` | 5 | 采样间隔 |
| `-p, --profile <Hz>` | 99 | perf 栈采样频率，0 表示禁用 |
| `-s, --schedstats` | 关 | 尝试开启内核 `sched_schedstats` 详细统计 |
| `--cpu-threshold <%>` | 90 | CPU 占用异常判定阈值 |
| `-j, --json` | 关 | 额外写入 report.json，供外部程序（如 AI 诊断）解析 |

### 3.3 io

| 参数 | 默认 | 说明 |
|---|---|---|
| `-i, --interval <秒>` | 3 | 采样间隔 |

### 3.4 mem

| 参数 | 默认 | 说明 |
|---|---|---|
| `-i, --interval <秒>` | 3 | 采样间隔 |
| `-a, --avail-threshold <百分比>` | 10 | 可用内存低水位阈值，低于视为异常 |
| `-f, --majfault-threshold <次/s>` | 200 | major fault 速率异常阈值 |

### 3.5 lock

| 参数 | 默认 | 说明 |
|---|---|---|
| `-i, --interval <秒>` | 5 | 采样间隔 |
| `-p, --profile <Hz>` | 0（禁用） | perf 栈采样频率，锁模块默认使用 futex 挂载点采栈 |
| `-j, --json` | 关 | 额外写入 report.json |

### 3.6 hot

| 参数 | 默认 | 说明 |
|---|---|---|
| `-i, --interval <秒>` | 5 | 采样间隔 |

---

## 4. 设计说明

### 4.1 总体架构

```
┌────────────────────────── 用户态 ──────────────────────────┐
│ main.c 子命令分发                                           │
│   ├─ cpu_anomaly.c ─┐                                      │
│   ├─ io_anomaly.c   │  周期性读取 BPF map → 聚合/阈值判定    │
│   ├─ mem_anomaly.c  ├─ → 根因分析 → 诊断报告                │
│   ├─ lock_anomaly.c │     (stdout / Markdown / JSON)       │
│   └─ syscall_anomaly.c ┘                                   │
└──────────────────────────┬─────────────────────────────────┘
                    BPF map（内核态聚合统计）
┌──────────────────────────┴───────────── 内核态 ────────────┐
│ *.bpf.c：tracepoint / kprobe / perf event 挂载点            │
│ sched_switch、block_rq_*、page_fault、futex、sys_enter/exit │
└─────────────────────────────────────────────────────────────┘
```

- **CO-RE (Compile Once, Run Everywhere)**：基于内核 BTF 生成 `vmlinux.h`，BPF 程序一次编译可跨内核版本运行，无需目标机器安装内核头文件。
- **内核态聚合**：统计在 BPF map 中按 PID/设备/系统调用号等维度累加，用户态按采样间隔批量读取并清零，避免每事件上报的开销。
- **skeleton 加载**：bpftool 生成 `.skel.h`，用户态通过 `open_and_load`/`attach` 一键加载挂载。

### 4.2 各模块检测原理

| 模块 | 数据来源 | 根因判定 |
|---|---|---|
| cpu | sched_switch / sched_stat_* / perf 采样（10 个 BPF 程序） | 结合 on-CPU 时间、上下文切换类型、调度延迟、栈集中度区分 CPU 密集、busy loop、锁竞争三类根因 |
| io | block 层 tracepoint（请求延迟、队列深度）、块重复读检测、热点文件追踪 | 延迟分位数 + IOPS/吞吐 + 缓存失效（短期重复读同块）综合诊断，区分 HDD/SSD |
| mem | 缺页（raw/completed）、直接回收、kswapd、OOM kill 探测 | eBPF 增量与 `/proc/<pid>/stat` 权威值对账；结合 /proc/meminfo、/proc/vmstat 判定内存抖动与回收压力 |
| lock | futex 等待时长/次数、等待点调用栈、热点锁地址 | 按锁地址聚合竞争者，线程 Tgid 归组，输出热点锁与等待栈 |
| hot | raw sys_enter/sys_exit 全量系统调用追踪 | 频次、耗时、错误率三维排序；区分等待型系统调用，进程级按耗时最多的系统调用判定根因（阻塞型 vs 轮询型） |

### 4.3 报告输出

- 纯文本诊断：Unicode 分隔线 + 中文标签 + 英文单位，含"疑似根因"与"建议"。
- Markdown 报告（`report_md.c`）：系统概览、TOP 进程表格、异常证据链、可折叠调用栈。
- JSON（`cpu`/`lock` 的 `-j`）：供 `ai_test/` 中的 AI 诊断脚本二次分析。

### 4.4 公共基础设施

`src/utils.c` 提供跨模块复用的能力：进程名读取（`read_comm`）、系统负载读取（`read_sys_metrics`）、地址符号化（`resolve_ip`，基于 /proc/pid/maps）、BPF map 清理（`reset_map`）、参数校验与输出文件管理等。

---

## 5. 限制说明

1. **必须 root 运行**：加载 BPF 程序、perf_event_open、读取内核 map 均需特权；容器内使用需特权容器并挂载 debugfs/tracefs。
2. **内核依赖**：要求内核开启 BTF（`CONFIG_DEBUG_INFO_BTF=y`）；无 BTF 的内核无法构建/运行（CO-RE 依赖）。目标内核 6.6+，更老内核的 tracepoint 格式差异未做适配。
3. **符号解析精度有限**：调用栈地址通过 `/proc/<pid>/maps` 解析为"模块+偏移"，不解析 DWARF/符号表，无法直接给出函数名；进程退出后栈地址无法回溯（显示原始地址），进程名显示 `<exited>`。
4. **短生命周期进程可能漏检**：统计按采样间隔批量读取，间隔内创建并退出的进程可能只留下部分指标，/proc 对账数据缺失。
5. **观测开销**：`hot` 模块追踪全量系统调用，高负载下有可感知开销；cpu/lock 的 perf 栈采样频率越高开销越大，可用 `-p 0` 禁用。
6. **阈值为静态配置**：异常判定阈值目前编译期确定（部分可经参数调整），尚不支持配置文件持久化（规划中）。
7. **暂无历史数据存储**：报告为单次快照，SQLite 历史存储与多维关联分析（如 I/O 缓存失效 + 内存抖动）在规划中。
8. **设备热插拔**：I/O 模块对已移除设备的 map 残留做了主动清理，但采样间隔内移除的设备可能出现一次不完整统计。
