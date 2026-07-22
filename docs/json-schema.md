# eebpf JSON 诊断报告格式规范

## 顶层结构

所有模块输出的 JSON 遵循统一顶层结构，文件路径为 `report/<module>.json`。

```json
{
  "module": "<模块名>",
  "timestamp": "<ISO 8601 时间>",
  "duration_s": <采样间隔秒数>,
  "system": { "<模块相关的系统级指标>" },
  "sections": [
    { "type": "table|kv|stacks|diagnosis", ... },
    ...
  ]
}
```

| 字段 | 类型 | 说明 |
|------|------|------|
| `module` | string | 模块名: `cpu`, `io`, `mem`, `lock`, `hot` |
| `timestamp` | string | 报告生成时间, ISO 8601 格式 `YYYY-MM-DDTHH:MM:SS` |
| `duration_s` | number | 采样窗口时长, 秒 |
| `system` | object | 系统级环境指标, 各模块字段不同 (见各模块章节) |
| `sections` | array | 报告内容区段, 按序排列 |

---

## Section 通用类型

每个 section 对象都有一个 `type` 字段决定其形态:

| type | 说明 | 必有额外字段 |
|------|------|-------------|
| `table` | 二维表格 | `title`, `columns`, `rows` |
| `kv` | 键值对列表 | `title`, `rows` |
| `stacks` | 调用栈概要 | `title`, `total_samples`, `top_stacks` |
| `diagnosis` | 诊断结论 | `title`, `findings` |

### table

```json
{
  "type": "table",
  "title": "表格标题",
  "columns": ["列1", "列2", ...],
  "rows": [
    ["值1", "值2", ...],
    ...
  ]
}
```

- `columns`: 字符串数组, 表头
- `rows`: 二维字符串数组, 每个元素与 `columns` 一一对应

### kv

```json
{
  "type": "kv",
  "title": "键值表标题",
  "rows": [
    { "key": "指标名", "value": "值" },
    ...
  ]
}
```

### stacks

```json
{
  "type": "stacks",
  "title": "栈采样概要",
  "total_samples": <总采样次数>,
  "top_stacks": [
    {
      "rank": 1,
      "count": <该栈采样次数>,
      "pct": <占比百分比>,
      "frames": ["帧0", "帧1", ...]
    }
  ]
}
```

- `total_samples`: number, 总采样次数
- `top_stacks`: array, 按采样次数降序 (通常 Top-5)
- `frames`: 字符串数组, `#0` 为栈顶, 格式 `<模块>!<函数>+<偏移>` 或 `<模块>+<偏移>`

### diagnosis

```json
{
  "type": "diagnosis",
  "title": "诊断结论",
  "findings": [
    {
      "target": "<诊断目标>",
      "is_anomaly": true|false,
      "subtype": "<异常子类型>",
      "root_cause": "<根因描述>",
      "suggestion": "<建议措施>",
      "time_window": "<时间窗口>",
      "key_metrics": { "<指标名>": "<值>", ... },
      "evidence": ["<证据1>", "<证据2>", ...]
    }
  ]
}
```

| 字段 | 类型 | 说明 |
|------|------|------|
| `target` | string | 诊断对象, 如进程名+PID / 系统调用名 / 设备名 |
| `is_anomaly` | boolean | 是否判定为异常 |
| `subtype` | string | 异常子类型标签, 见各模块枚举 |
| `root_cause` | string | 疑似根因, 一行中文描述 |
| `suggestion` | string | 排查或优化建议 |
| `time_window` | string | 诊断窗口, 格式 `时间 +间隔s` |
| `key_metrics` | object | 支撑诊断的关键指标, 键值对 |
| `evidence` | string[] | 证据描述列表 |

---

## 各模块规范

### 1. CPU 异常检测 (`cpu`)

**文件**: `report/cpu.json`

#### system 字段

| 键 | 类型 | 说明 |
|----|------|------|
| `CPU 核心数` | string | 在线 CPU 数 |
| `活跃进程数` | string | 采样到的活跃进程数 |
| `调度器` | string | 当前调度器名称, 如 `CFS`, `EEVDF` |
| `抢占模型` | string | 内核抢占模型, 如 `voluntary`, `full` |
| `schedstats` | string | schedstats 是否启用 |
| `系统负载 (1m/5m/15m)` | string | loadavg |
| `RunQ 深度 (瞬时)` | string | 瞬时运行队列长度 |
| `不可中断阻塞` | string | 不可中断睡眠进程数 |
| `CPU 异常阈值` | string | 配置的 CPU 异常判定阈值 |

#### sections

| 顺序 | type | title | 说明 |
|------|------|-------|------|
| 1 | `stacks` | 栈采样概要 | 出现条件: 有栈采样数据 |
| 2 | `table` | CPU 异常进程 Top-15 | 进程级 CPU 占用排行 |
| 3 | `diagnosis` | CPU 异常诊断分析 | 进程级 + 系统级诊断 |

#### diagnosis subtype 枚举

| subtype | 说明 |
|---------|------|
| `CPU 密集计算` | 用户态计算密集型 CPU 高占用 |
| `busy loop` | 运行时特征匹配 spin-wait |
| `锁竞争 (futex 等待)` | run_delay 占比高, 伴随 futex 等待 |
| `内存压力 (回收/缺页)` | 伴随大量内存回收或缺页 |
| `调度器抖动 (频繁迁移)` | 进程频繁在核间迁移 |
| `高负载 (系统级)` | 系统整体 CPU 超阈值, 非单进程 |

---

### 2. I/O 异常检测 (`io`)

**文件**: `report/io.json`

#### system 字段

| 键 | 类型 | 说明 |
|----|------|------|
| `活跃块设备数` | string | 有 I/O 活动的块设备数 |
| `系统负载 (1m/5m/15m)` | string | loadavg |

#### sections

| 顺序 | type | title | 说明 |
|------|------|-------|------|
| 1 | `table` | 设备 I/O 统计 | 设备级 I/O 指标 |
| 2 | `table` | 热点文件 Top-20 | 出现条件: 有热点文件数据 |
| 3 | `diagnosis` | I/O 异常诊断分析 | 设备级诊断 |

#### diagnosis subtype 枚举

| subtype | 说明 |
|---------|------|
| `I/O 延迟抖动` | P99 或 P99.9 偏高 |
| `I/O 队列拥塞` | 队列深度占比高 |
| `I/O 缓存失效` | 缓存失效率高 |
| `I/O 热文件` | 特定文件 I/O 密集 |
| `I/O 多设备高负载` | 多设备同时高 I/O |

---

### 3. 内存异常检测 (`mem`)

**文件**: `report/mem.json`

#### system 字段

| 键 | 类型 | 说明 |
|----|------|------|
| `总内存` | string | 物理内存总量 |
| `可用内存` | string | 可用内存及百分比 |
| `Swap` | string | Swap 使用量及百分比 |
| `系统负载 (1m/5m/15m)` | string | loadavg |

#### sections

| 顺序 | type | title | 说明 |
|------|------|-------|------|
| 1 | `kv` | 内存容量快照 | /proc/meminfo 摘要 |
| 2 | `table` | 内存压力指标 | 缺页/回收/OOM 速率 |
| 3 | `table` | 进程内存 Top-15 | 进程级内存占用排行 |
| 4 | `table` | 抖动审计 | 高频缺页/回收进程 |
| 5 | `diagnosis` | 内存异常诊断分析 | 进程级 + 系统级诊断 |

#### diagnosis subtype 枚举

| subtype | 说明 |
|---------|------|
| `内存高占用` | 进程内存占比超阈值 |
| `内存抖动` | 高频缺页或内存回收 |
| `内存压力 (系统级)` | 可用内存低于阈值 |
| `Swap 压力` | Swap 使用率过高 |

---

### 4. 锁竞争检测 (`lock`)

**文件**: `report/lock.json`

#### system 字段

| 键 | 类型 | 说明 |
|----|------|------|
| `全局 futex 等待次数` | string | 观测窗口内 futex 等待总次数 |
| `全局平均 futex 等待` | string | 全局平均 futex 等待耗时 |
| `全局 futex 总等待时间` | string | futex 等待总时间 |
| `系统负载 (1m/5m/15m)` | string | loadavg |
| `活跃锁竞争进程数` | string | 检测到锁竞争的进程数 |

#### sections

| 顺序 | type | title | 说明 |
|------|------|-------|------|
| 1 | `table` | 热点锁 Top-10 | 出现条件: 有热点锁数据 |
| 2 | `stacks` | 栈采样概要 | 出现条件: 有栈采样数据 |
| 3 | `diagnosis` | 锁竞争诊断分析 | 进程级诊断 |

#### diagnosis subtype 枚举

| subtype | 说明 |
|---------|------|
| `锁竞争` | 进程 futex 等待占比过高 |
| `锁竞争 + 栈热点` | 含调用栈的锁竞争分析 |

---

### 5. 系统调用热点 (`hot`)

**文件**: `report/hot.json`

#### system 字段

| 键 | 类型 | 说明 |
|----|------|------|
| `系统调用总数` | string | 观测窗口内系统调用总次数 |
| `总耗时` | string | 系统调用总耗时 |
| `错误数` | string | 系统调用错误返回次数 |

#### sections

| 顺序 | type | title | 说明 |
|------|------|-------|------|
| 1 | `table` | 高频系统调用 Top-10 | 按调用次数排序 |
| 2 | `table` | 高耗时系统调用 Top-10 | 按平均耗时排序 |
| 3 | `table` | 进程系统调用汇总 | 进程级系统调用统计 |
| 4 | `diagnosis` | 诊断结论 | 系统调用级 + 进程级诊断 |

#### diagnosis subtype 枚举

| subtype | 说明 |
|---------|------|
| `高频调用` | 每秒调用次数超阈值, busy-poll 特征 |
| `高耗时` | 平均耗时超阈值, 阻塞型系统调用 |
| `高频 + 高耗时` | 调用频率和耗时均超阈值 |
| `高错误率` | 错误率超阈值 |
| `等待 (正常)` | 等待型系统调用 (epoll_wait 等), 高耗时属正常语义 |

#### 等待型系统调用列表

`poll`, `select`, `epoll_wait`, `epoll_pwait`, `epoll_pwait2`, `nanosleep`, `clock_nanosleep`, `pselect6`, `ppoll`

这些系统调用在 `is_anomaly` 为 `false`, `subtype` 为 `等待 (正常)`。

---

## 字段完整性校验

每个 diagnosis finding 必须包含全部 8 个字段:

```
target, is_anomaly, subtype, root_cause, suggestion, time_window, key_metrics, evidence
```

Python 校验脚本:

```python
import json

REQUIRED = ('target', 'is_anomaly', 'subtype', 'root_cause',
            'suggestion', 'time_window', 'key_metrics', 'evidence')

for mod in ('cpu', 'io', 'mem', 'lock', 'hot'):
    path = f'report/{mod}.json'
    try:
        with open(path) as f:
            data = json.load(f)
    except FileNotFoundError:
        print(f'{mod}: SKIP (文件不存在)')
        continue
    for sec in data.get('sections', []):
        if sec.get('type') != 'diagnosis':
            continue
        for finding in sec.get('findings', []):
            missing = [k for k in REQUIRED if k not in finding]
            if missing:
                print(f'{mod}: 缺少字段 {missing}')
            else:
                print(f'{mod}: {finding["target"]} -> {finding["subtype"]}  OK')
```
