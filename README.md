# eebpf — eBPF 系统异常观测与根因定位工具

基于 eBPF (libbpf + BPF CO-RE) 的轻量级系统异常观测与根因定位工具，覆盖 5 类异常场景，输出结构化 Markdown / JSON 诊断报告 + JSON 结构化数据。

目标运行环境：openKylin / debian系, x86_64 / ARM64。

## 用户手册

详见 [docs/manual.md](docs/manual.md) — 安装说明、构建指南、配置详解、各模块使用说明。

## 快速开始

### 方式一：Deb/RPM 包安装

从 [Releases](https://github.com/X2002w/ebpf/releases) 下载最新版本对应架构的安装包。

**Debian/Opebkylin (deb)**：

```bash
# 安装
sudo apt install ./eebpf_*_amd64.deb

# 运行（需要 root）
sudo eebpf cpu -d 10
sudo eebpf-ai report/ -m cpu,mem
```

> 卸载：`sudo apt remove eebpf`

**RHEL/Centos (rpm)**：

```bash
# 安装
sudo rpm -ivh eebpf-*.x86_64.rpm

# 或使用 dnf/yum 自动处理依赖
sudo dnf install ./eebpf-*.x86_64.rpm

# 运行（需要 root）
sudo eebpf cpu -d 10
sudo eebpf-ai report/ -m cpu,mem
```

> 卸载：`sudo rpm -e eebpf`

**配置 API key**（AI 诊断功能）：

编辑 `/usr/share/eebpf/ai_analysis/api_config.json`，将 `api_key` 字段替换为你的密钥：

```bash
sudo vim /usr/share/eebpf/ai_analysis/api_config.json
```

```json
{
    "api_key": "sk-your-key",
    "base_url": "https://api.deepseek.com",
    "model": "deepseek-v4-pro"
}
```

也可创建用户级配置（优先级高于系统级）：
```bash
mkdir -p ~/.eebpf/ai_analysis 
cp /usr/share/eebpf/ai_analysis/api_config.json ~/.eebpf/ai_analysis/
# 然后编辑 
~/.eebpf/ai_analysis/api_config.json
```
> 本地测试也可用 `echo "sk-your-key" > ai_analysis/api.txt`（gitignore 保护，优先级高于 json）。

### 方式二：源码构建

```bash
git clone https://github.com/X2002w/eebpf.git && cd eebpf
# 拉取源码后建议 checkout 到最新 tag
```

**手动构建：**

```bash
./start.sh                           # 环境检查 + 依赖安装
make                                 # 构建
sudo ./eebpf -v                      # 验证版本
sudo ./eebpf cpu -d 10               # 运行
```

**一键部署脚本：**

```bash
sudo ./scripts/setup.sh              # 依赖检查 → 构建 → 场景复现
```

### 方式三：Docker 部署

```bash
git clone https://github.com/X2002w/eebpf.git && cd eebpf

# 建议优先使用快捷脚本
./enter-container.sh

# 或者手动启动
# 启动容器（需要 sudo，容器需要 privileged + BPF 权限）
sudo docker compose build --pull && sudo docker compose up -d

# 进入容器
sudo docker compose exec openkylin bash -c "cd /workspace && exec bash"
```

> 容器内 `/workspace` 已挂载项目源码，可直接 `make` 构建并运行。

### 通用 CLI 参数

| 选项 | 说明 |
|------|------|
| `-i, --interval <秒>` | 采样间隔（默认: 5） |
| `-d, --duration <秒>` | 总运行时长，0 表示持续运行 |
| `-o, --output <路径>` | 文本报告输出文件（默认: stdout） |
| `-j, --json` | 额外输出 JSON + Markdown 报告到 `report/` 目录 |
| `-h, --help` | 显示帮助 |

### 子命令

| 子命令 | 说明 |
|------|------|
| `cpu` | CPU 异常检测（CPU 密集/busy loop/锁竞争三根因分类） |
| `io` | I/O 异常检测（延迟/队列/缓存失效/热点文件/多设备） |
| `mem` | 内存异常检测（OOM/换页颠簸/缓存颠簸/回收抖动/缺页激增） |
| `lock` | 锁竞争检测（futex 等待/阻塞分析/等待点调用栈） |
| `hot` | 系统调用热点分析（频率/耗时/错误率） |
| `correlate` | 多维关联分析（跨模块规则引擎，时间窗口匹配） |
| `history` | SQLite 历史趋势查询（基线/趋势/异常回溯） |

### 使用示例

```bash
# 通用模板
sudo eebpf <子命令> [-i <秒>] [-d <秒>] [-o <路径>] [-j]

# CPU 异常检测
sudo eebpf cpu -i <间隔> -d <时长> [-o <输出文件>] [-j]
sudo eebpf cpu -i 3 -d 60 -o cpu_report.txt       # 实际示例

# I/O 异常检测
sudo eebpf io [-i <间隔>] [-d <时长>] [-j]
sudo eebpf io -d 0 -j                              # 实际示例：持续运行 + JSON

# 内存异常检测
sudo eebpf mem [-i <间隔>] [-d <时长>] [-j]
sudo eebpf mem -d 30                               # 实际示例

# 锁竞争检测
sudo eebpf lock [-i <间隔>] [-d <时长>] [-j]
sudo eebpf lock -i 1 -d 0                          # 实际示例：每秒采样，持续运行

# 系统调用热点分析
sudo eebpf hot [-i <间隔>] [-d <时长>] [-o <输出文件>] [-j]
sudo eebpf hot -d 120 -j -o hot_report.txt         # 实际示例

# 多维关联分析
sudo eebpf correlate [-m <模块列表>]
sudo eebpf correlate -m cpu,mem,io                 # 实际示例

# 历史趋势查询
sudo eebpf history [-m <模块>] [-t <时间范围>]
sudo eebpf history -m cpu -t 60                    # 实际示例
```

### 配置文件

通过 `eebpf.conf` 自定义阈值和参数，查找路径: `./eebpf.conf` > `~/.eebpf.conf` > `/etc/eebpf.conf`。

```ini
# 采样间隔 (秒)
interval = 5

# CPU 异常阈值 (%)
cpu_threshold = 90

# 系统调用热点阈值
hot_freq_per_sec = 10000
hot_lat_us = 10000
hot_err_rate = 0.1
```

## 输出格式

诊断报告输出到项目根目录下的 `report/` 目录，使用 `-j` 标志后自动创建。

| 文件 | 说明 |
|------|------|
| `report/<module>.json` | 结构化 JSON 诊断数据 |
| `report/<module>.md` | JSON 自动渲染的 Markdown 报告 |
| `report/demo_summary.md` | 场景复现测试汇总报告（`scripts/reproduce.sh` 生成） |
| `report/benchmark.md` | 性能基准测试报告（`scripts/bench.sh` 生成） |

- **Markdown 报告**: 可读性强的格式化诊断报告
- **JSON 报告**: 结构化数据，供 AI 诊断模块或外部工具消费

JSON 格式详见 [docs/json-schema.md](docs/json-schema.md)。

## 文档索引

| 文档 | 说明 |
|------|------|
| [docs/manual.md](docs/manual.md) | 用户手册：安装、构建、配置、各模块使用指南 |
| [docs/test-guide.md](docs/test-guide.md) | 测试说明：一键部署、场景复现、性能基准、JSON 校验 |
| [docs/json-schema.md](docs/json-schema.md) | JSON 输出格式规范：顶层结构、section 类型、diagnosis 字段定义 |
| [docs/collected_data.md](docs/collected_data.md) | 各模块 BPF 采集数据字典：map key/value、字段类型与来源 |
| [docs/compat-matrix.md](docs/compat-matrix.md) | 多平台适配矩阵：x86_64/ARM64 × 内核 6.1/6.6/6.12 |
| [docs/anomaly-detection.md](docs/anomaly-detection.md) | 异常检测方案：固定阈值 + 基线自适应双轨机制 |
| [docs/correlate.md](docs/correlate.md) | 多维关联分析：跨模块规则引擎、关联规则与使用说明 |

## 脚本索引

| 脚本 | 说明 |
|------|------|
| `start.sh` | 环境依赖一键检查与安装（构建工具、运行时库、压力工具、AI 诊断环境） |
| `enter-container.sh` | 构建并进入 openKylin Docker 开发容器 |
| `scripts/setup.sh` | 一键部署：依赖检查 → 构建 → 场景复现全流程 |
| `scripts/reproduce.sh` | 赛题场景复现：stress-ng/fio 注入异常 → eebpf 检测 → 生成对比报告 |
| `scripts/bench.sh` | 性能基准测试：测量 CPU/内存/I/O 四项开销 |
| `scripts/ai_check_env.sh` | AI 诊断环境自检 |

## AI 多模块联合诊断

`ai_analysis/` 目录包含基于大模型的跨模块关联分析工具，读取 eebpf JSON 报告进行根因推断。

```bash
# 初始化环境
./start.sh

# 配置 API key（编辑 api_config.json）
# 或本地测试用: echo "sk-your-key" > ai_analysis/api.txt

# 运行诊断
# 在运行前，确保requestments里要求的python库以及下载,可自行选择py解释器，不一定
# 必须得是下面这个路径(这个路径是在本地测试时创建的虚拟环境)
./ai_analysis/venv/bin/python ai_analysis/caller.py report/ -m cpu,mem,io
```

API 兼容 OpenAI 接口的任意后端（DeepSeek、通义千问等），编辑 `ai_analysis/api_config.json` 切换。

### AI 诊断 5 项上下文能力

`caller.py` 生成 prompt 时附带 5 类上下文（需 `storage_enabled=1` 才能取到基线/趋势/关联）：

| 能力 | 来源 | 用途 |
|------|------|------|
| 基线 | history 表 + Welford 在线统计 | 区分稳态与异常波动 |
| 趋势 | 最近 N 条同模块记录 | 展示指标变化方向 |
| 关联 | correlate 输出 | 跨模块根因链 |
| 规则 | 各模块 finding 的 evidence | 给出判定依据 |
| 时间戳 | finding time_window | 异常时间窗定位 |

### 自定义系统提示词

编辑 `ai_analysis/system_prompt.md` 即可自定义发送给大模型的系统提示词，无需修改代码。`caller.py` 启动时自动加载该文件内容作为 system prompt，若文件不存在则使用内置简化版。

安装后文件路径（与 `api_config.json` 相同）：
- 系统级：`/usr/share/eebpf/ai_analysis/system_prompt.md`
- 用户级（优先级更高）：`~/.eebpf/ai_analysis/system_prompt.md`

可自定义的内容示例：
- 调整报告输出语言和风格
- 追加特定分析维度（如网络、GPU）
- 修改根因推断的侧重点或优先级
- 添加领域特定的诊断经验规则

## 多维关联分析

`correlate` 子命令读取各模块已写入的报告，按规则引擎做跨模块时间窗匹配，输出关联诊断。例如 I/O 缓存失效与内存抖动在 ±60s 内同时出现即判定为相关。

```bash
# 默认 60s 窗口
sudo eebpf correlate -j

# 自定义窗口
sudo eebpf correlate --window 120 -j
```

## 历史趋势查询

采集报告默认写入 `report/eebpf.db`（SQLite）。`history` 子命令查询指定模块的时间线。

```bash
# 查询 CPU 模块最近 20 条记录
sudo eebpf history cpu

# JSON 输出 + 限制条数
sudo eebpf history mem -j -n 50

# 执行自定义 SQL
sudo eebpf history --sql "SELECT * FROM findings WHERE module='io' LIMIT 10"

# 清空历史
sudo eebpf history --clear
```

## 构建要求

- clang (19+)、bpftool、make
- libbpf、libelf、zlib 开发库
- 内核开启 `CONFIG_DEBUG_INFO_BTF`（`/sys/kernel/btf/vmlinux` 存在）

```bash
make clean && make
```

## CI/CD

GitHub Actions 自动化构建、测试与发布（详见 [docs/compat-matrix.md](docs/compat-matrix.md)）:

| 工作流 | 触发条件 | 说明 |
|------|------|------|
| **Build Test** | push / PR | openKylin 容器内快速编译验证 |
| **ARM64 Build** | push / PR | ARM64 原生构建 + 全模块冒烟测试 |
| **Kernel Matrix** | push / PR | virtme-ng 启动 6.1 / 6.6 / 6.12 内核真实加载 BPF |
| **Packaging Test** | push / PR | 打包 deb → apt 安装 → 冒烟测试 (amd64 + arm64) |
| **Docker Publish** | push / PR | 构建 Docker 镜像并推送到 GHCR|
| **Release** | tag `v*` | 构建 → 安装验证 → GitHub Release 自动发布 |
| **Cleanup Old Packages** | 定期 | 自动清理过期构建产物与旧版本包 |

## TODO

- [x] CPU 异常占用或调度延迟
- [x] 设置schedstats 性能分析时开启
- [x] 修复容器环境里bpftool安装失败问题 -> 从源码构建(容器构建时)
- [x] 在docker-compose.yml 里挂载宿主机的必要目录
- [x] 添加confige文件，存储用户在使用cli工具使得配置信息
- [x] io 异常
- [x] dev_stats dev_t作为map key, 在设备移除后，map条目变为僵尸数据，主动清理(/proc/partitions)读取设备列表
- [x] 设备号 dev_t 使用两条路径拿取(rq->part->bd_dev) or (rq->q->disk->major / first_minor)
- [x] 使用另外的fio测试命令，原测试命令体现不出io异常
- [x] 考虑去除ii_qdepth
- [x] ai诊断时, 添加原始系统设备数据, 为BPF 得到的基础数据做参考
- [x] io 缓存失效 检测同块短时间内重复读，即缓存失效(cache 空间被占满)
- [x] io缓存失效 <- 内存抖动佐证 (多维关联分析)
- [x] 重构项目
- [x] cicd自动构建发布镜像
- [x] 将下载LLVM从build test action移到dockr build action 中
- [x] 将各部分监测程序的公共宏放置再一起 or 使用config文件编辑
- [x] 使用sqlite存储历史数据
- [x] 加前瞻性6.1, 6.6, 6.12, stable —— stable 标签自动追新内核，将来内核更新破坏兼容性时 CI 会第一时间红
- [x] 重构文档输出报告
- [x] AI 多模块联合诊断 (ai_analysis/)
- [x] 打包发布（make install + pyproject.toml）
- [x] 添加各文档之间的相互引用
- [x] 修正report报告路径默认为项目根目录下report目录
- [ ] 当前项目无并发,考虑将py调用大模型更换为curl调用
- [x] 分离打包，deb内添加说明
- [x] 插件化扩展,子命令注册机制抽象,支持加载自定义检测模块
- [ ] 考虑AI 诊断支持保证离线环境可复现 or 添加免费限额api key
