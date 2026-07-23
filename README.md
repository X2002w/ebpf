# eebpf — eBPF 系统异常观测与根因定位工具

基于 eBPF (libbpf + BPF CO-RE) 的轻量级系统异常观测与根因定位工具，覆盖 5 类异常场景，输出结构化 Markdown 诊断报告 + JSON 结构化数据。

目标运行环境：openKylin / debian系, Kernel 6.6+, x86_64 / ARM64。

## 用户手册

详见 [docs/manual.md](docs/manual.md) — 安装说明、构建指南、配置详解、各模块使用说明。

## 快速开始

```bash
# 克隆仓库
git clone https://github.com/X2002w/ebpf.git && cd ebpf

# 环境检查 + 依赖安装
./start.sh

# 构建
make

# 运行（需要 root）
sudo ./eebpf cpu -d 10        # CPU 异常检测, 运行 10 秒
sudo ./eebpf io  -d 10        # I/O 异常检测
sudo ./eebpf mem -d 10        # 内存异常检测
sudo ./eebpf lock -d 10       # 锁竞争检测
sudo ./eebpf hot -d 10        # 系统调用热点

# 输出 JSON 报告
sudo ./eebpf cpu -j -d 30     # report/cpu.json + report/cpu.md
```

### 通用 CLI 参数

| 选项 | 说明 |
|------|------|
| `-i, --interval <秒>` | 采样间隔（默认: 5） |
| `-d, --duration <秒>` | 总运行时长，0 表示持续运行 |
| `-o, --output <路径>` | 文本报告输出文件（默认: stdout） |
| `-j, --json` | 额外输出 JSON + Markdown 报告到 `report/` 目录 |
| `-h, --help` | 显示帮助 |

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

# 配置 API key
echo "sk-your-key" > ai_analysis/api.txt(本地测试)

# 运行诊断
./ai_analysis/venv/bin/python ai_analysis/caller.py report/ -m cpu,mem,io
```

API 兼容 OpenAI 接口的任意后端（DeepSeek、通义千问等），编辑 `ai_analysis/api_config.json` 切换。

### 自定义系统提示词

编辑 `ai_analysis/system_prompt.md` 即可自定义发送给大模型的系统提示词，无需修改代码。`caller.py` 启动时自动加载该文件内容作为 system prompt，若文件不存在则使用内置简化版。

可自定义的内容示例：
- 调整报告输出语言和风格
- 追加特定分析维度（如网络、GPU）
- 修改根因推断的侧重点或优先级
- 添加领域特定的诊断经验规则

## 构建要求

- clang (19+)、bpftool、make
- libbpf、libelf、zlib 开发库
- 内核开启 `CONFIG_DEBUG_INFO_BTF`（`/sys/kernel/btf/vmlinux` 存在）

```bash
make clean && make
```

## CI/CD

GitHub Actions 覆盖三类自动化验证（详见 [docs/compat-matrix.md](docs/compat-matrix.md)）:

- **Project Build**: openKylin 2.0 容器内完整构建
- **Kernel Matrix**: virtme-ng 启动 6.1 / 6.6 / 6.12 内核，真实挂载 BPF 程序冒烟测试
- **ARM64**: ARM64 原生构建 + 5 个子命令真实加载 BPF 冒烟

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
- [ ] io缓存失效 <- 内存抖动佐证 (多维关联分析)
- [x] 重构项目
- [x] cicd自动构建发布镜像
- [x] 将下载LLVM从build test action移到dockr build action 中
- [x] 将各部分监测程序的公共宏放置再一起 or 使用config文件编辑
- [ ] 使用sqlite存储历史数据
- [x] 加前瞻性6.1, 6.6, 6.12, stable —— stable 标签自动追新内核，将来内核更新破坏兼容性时 CI 会第一时间红
- [x] 重构文档输出报告
- [x] AI 多模块联合诊断 (ai_analysis/)
- [ ] 打包发布（make install + pyproject.toml）
- [x] 添加各文档之间的相互引用
- [ ] 修正report报告路径默认为项目根目录下report目录
- [ ] 当前项目无并发,考虑将py调用大模型更换为curl调用
- [ ] 分离打包，deb内添加说明
