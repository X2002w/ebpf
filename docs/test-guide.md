# eebpf 测试说明

## 1.0 测试环境

| 项目 | 要求 |
|------|------|
| 操作系统 | openKylin / Debian（其他 Linux 发行版亦可） |
| 内核版本 | 6.6+，需开启 `CONFIG_DEBUG_INFO_BTF` |
| 架构 | x86_64 / ARM64 |
| 权限 | root（加载 BPF 程序、perf 采样需要特权） |
| 依赖 | clang, libbpf, libelf, zlib, bpftool |

## 2.0 一键部署测试

```bash
# 克隆仓库
git clone https://github.com/X2002w/ebpf.git && cd ebpf

# 一键部署 — 安装依赖 → 构建 → 场景复现
sudo ./scripts/setup.sh
```

## 3.0 自动化场景测试

```bash
# 场景复现测试（4 个赛题场景，逐个运行并验证检测结果）
sudo ./scripts/reproduce.sh
```

测试用 stress-ng 和 fio 注入赛题指定的 4 类异常负载，每场景运行 eebpf 对应模块，自动提取检测结果并与期望根因匹配，输出汇总报告 `report/demo_summary.md`。

### 3.1 测试步骤

| 序号 | 场景 | 注入命令 | eebpf 模块 | 期望根因关键词 |
|------|------|----------|-----------|---------------|
| 1 | CPU 密集 | stress-ng --cpu 4 matrixprod | cpu | CPU 密集 |
| 2 | I/O 抖动 | fio randrw iodepth=64 direct=1 | io | I/O |
| 3 | 内存压力 | stress-ng --vm 4 80% --vm-keep | mem | 内存 |
| 4 | 锁竞争 | stress-ng --mutex 8 | lock | 锁竞争 |
| 5 | 系统调用热点 | stress-ng --cpu 4 matrixprod | hot | 高频调用 |

### 3.2 输出文件

| 文件 | 说明 |
|------|------|
| `report/cpu_demo.json` | CPU 场景 JSON 诊断报告 |
| `report/io_demo.json` | I/O 场景 JSON 诊断报告 |
| `report/mem_demo.json` | 内存场景 JSON 诊断报告 |
| `report/lock_demo.json` | 锁竞争场景 JSON 诊断报告 |
| `report/hot_demo.json` | 系统调用热点 JSON 诊断报告 |
| `report/demo_summary.md` | 汇总表格，含匹配结果 |

### 3.3 结果示例

| 场景             | 模块 | 检测结果                   | 异常数 | 匹配期望 |
|------------------|------|----------------------------|--------|----------|
| CPU 密集计算     | cpu  | CPU异常占用 (CPU 密集计算) | 4      | ✓        |
| I/O 随机读写抖动 | io   | I/O 延迟抖动               | 1      | ✓        |
| 内存压力与抖动   | mem  | 内存抖动 (缺页颠簸)        | 1      | ✓        |
| futex 锁竞争     | lock | 锁竞争 (热点锁集中)        | 18     | ✓        |
| 系统调用热点     | hot  | 高频调用                   | -      | ✓        |

## 4.0 手动单项测试

### 4.1 CPU 异常检测

```bash
# 终端 1: 注入 CPU 负载
stress-ng --cpu 4 --cpu-method matrixprod --timeout 60s

# 终端 2: 运行 eebpf
sudo ./eebpf cpu -d 30
```

**预期**: JSON 输出 `subtype` 包含 "CPU 密集计算" 或 "busy loop"，`is_anomaly: true`。

### 4.2 I/O 异常检测

```bash
# 终端 1: 注入 I/O 负载（需写到真实块设备，非 tmpfs）
fio --name=test --filename=$HOME/fio-test.img --size=2G \
    --rw=randrw --bs=4k --iodepth=64 --numjobs=4 \
    --runtime=60 --time_based --direct=1 --ioengine=libaio

# 终端 2: 运行 eebpf
sudo ./eebpf io -d 30
```

**预期**: JSON 输出 `subtype` 包含 "I/O 延迟抖动" 或 "队列"，`is_anomaly: true`。

### 4.3 内存异常检测

```bash
# 终端 1: 注入内存压力
stress-ng --vm 4 --vm-bytes 80% --vm-keep --timeout 60s

# 终端 2: 运行 eebpf
sudo ./eebpf mem -d 30
```

**预期**: JSON 输出 `subtype` 包含 "内存抖动" 或 "内存高占用"。

### 4.4 锁竞争检测

```bash
# 终端 1: 注入锁竞争
stress-ng --mutex 8 --timeout 60s

# 终端 2: 运行 eebpf
sudo ./eebpf lock -d 30
```

**预期**: JSON 输出 `subtype` 包含 "锁竞争"，`is_anomaly: true`。

### 4.5 系统调用热点分析

```bash
# 终端 1: 注入系统调用密集负载 (CPU 密集计算会触发大量 syscall)
stress-ng --cpu 4 --cpu-method matrixprod --timeout 60s

# 终端 2: 运行 eebpf
sudo ./eebpf hot -d 30
```

**预期**: JSON 输出高频/高耗时系统调用 Top-N 列表，`subtype` 包含 "高频调用" 或 "高耗时"。

## 5.0 eebpf程序性能基准测试

```bash
sudo ./scripts/bench.sh
```

测试 4 项开销并输出 `report/benchmark.md`：

| 指标 | 测试方法 |
|------|----------|
| CPU 开销 | /proc/stat 系统 CPU 差值 |
| 内存开销 | VmRSS + bpftool map memlock |
| I/O P99 时延 | fio clat_ns 百分位 |
| I/O 吞吐 | fio IOPS / BW |

### 5.1 基准结果参考

测试环境: x86_64, Kernel 6.12, NVMe SSD, 4 核 CPU

| 指标 | 基线 | 有 eebpf | 影响 |
|------|------|----------|------|
| 系统 CPU | 56% | 54% | 可忽略 |
| 进程 RSS | - | 2.8 MB | 极低 |
| BPF map | - | 14.8 MB | - |
| I/O P99 | 1μs | 1μs | 0% |
| IOPS | 408671 | 410160 | 0.3% |

## 6.0 JSON 输出验证

诊断 finding 应包含全部 7 个必填字段：

```json
{
  "target": "stress-ng-cpu(12345)",
  "is_anomaly": true,
  "subtype": "CPU异常占用 (CPU 密集计算)",
  "root_cause": "用户态 CPU 密集型计算致 CPU 饱和",
  "suggestion": "审查计算热点函数",
  "time_window": "2026-07-21T22:29:00 +15s",
  "key_metrics": { "CPU 占用": "92.0%" },
  "evidence": ["CPU 占用 92.0%, 超过阈值 90%"]
}
```

可通过 Python 快速校验字段完整性：

```bash
python3 -c "
import json
required = ('target', 'is_anomaly', 'subtype', 'root_cause', 'suggestion', 'time_window', 'key_metrics', 'evidence')
for mod in ('cpu', 'io', 'mem', 'lock'):
    with open(f'report/{mod}.json') as f:
        data = json.load(f)
    for sec in data.get('sections', []):
        if sec.get('type') == 'diagnosis':
            for finding in sec.get('findings', []):
                for k in required:
                    assert k in finding, f'{mod}: missing {k}'
                print(f'{mod}: {finding[\"target\"]} → {finding[\"subtype\"]}  ✓')
"
```

## 7.0 多维关联与历史查询

### correlate 规则引擎

`correlate` 子命令读取已写入的 JSON 报告，按内置规则做跨模块时间窗匹配：

```bash
# 先跑各模块采集（写入 report/*.json 与 eebpf.db）
sudo eebpf cpu -d 10 -j
sudo eebpf io -d 10 -j
sudo eebpf mem -d 10 -j

# 60s 窗口关联
sudo eebpf correlate -j
```

输出包含匹配到的规则名、关联模块、对应时间窗与关键指标。

### history 时间线查询

历史数据写入 `report/eebpf.db`（SQLite）。查询示例：

```bash
sudo eebpf history cpu -n 20
sudo eebpf history mem -j -n 50
sudo eebpf history --sql "SELECT module,subtype,timestamp FROM findings ORDER BY timestamp DESC LIMIT 20"
```

### AI 诊断 5 项上下文能力

`ai_analysis/caller.py` 在生成 prompt 时附带 5 类上下文（需 `storage_enabled=1`）：

| 能力 | 来源 | 用途 |
|------|------|------|
| 基线 | `history` 表 + Welford 在线统计 | 区分稳态与异常波动 |
| 趋势 | 最近 N 条同模块记录 | 展示指标变化方向 |
| 关联 | `correlate` 输出 | 跨模块根因链 |
| 规则 | 各模块 finding 的 `evidence` | 给出判定依据 |
| 时间戳 | finding `time_window` | 异常时间窗定位 |

