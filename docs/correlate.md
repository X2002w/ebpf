# eebpf 多维关联分析（correlate）

correlate 读取各模块已有的 findings，通过硬编码规则引擎匹配跨模块时间窗口共现模式，将单模块发现串联为根因链。它不运行 eBPF 程序。

## 数据来源

| 条件 | 数据源 | 范围 |
|------|--------|------|
| `storage_enabled = 1` | SQLite `findings` 表 | 最近 3600s |
| `storage_enabled = 0` | `report/*.json` | 全部 |

`--window` 仅影响匹配窗口，不影响读取范围。

## 规则引擎

每条规则由三要素组成：subtype 子串匹配、可选指标条件（`key>N` / `key<N` 等）、时间窗口（两侧时间戳差 ≤ `--window`）。关系类型分为 `causal`（因果）、`confirm`（印证）、`co-occur`（伴随）。部分规则为单侧（B 侧为空），标记"存在异常但无其它模块佐证"。

## CLI

```bash
sudo eebpf correlate                  # 默认 60s 窗口
sudo eebpf correlate --window 120     # 自定义窗口
sudo eebpf correlate -j               # JSON 输出
```

| 参数 | 说明 |
|------|------|
| `-w, --window` | 时间窗口（秒），默认 60 |
| `-j, --json` | JSON 输出 |
| `-o, --output` | 输出文件路径 |

## 前置条件

需先运行各模块产出 findings（`-j` 输出 JSON 或开启 `storage_enabled` 写入 SQLite）：

```bash
sudo eebpf cpu -d 30 -j && sudo eebpf io -d 30 -j
sudo eebpf correlate -j
```

## 配置

无专用配置项，依赖 `storage_enabled` 切换数据源。

## 局限

- 规则硬编码在 `src/correlate.c`，修改需重新编译
- 同一 finding 可能被多条规则命中，无去重
- 读 SQLite 固定取最近 3600s，不受 `--window` 影响
