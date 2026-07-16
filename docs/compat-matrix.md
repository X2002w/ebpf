# eebpf 多平台适配矩阵

本表汇总 eebpf 在不同操作系统、内核版本与硬件架构上的验证结果。
除"本地实测"外均由 GitHub Actions 自动化验证，可持续回归。

## 适配矩阵

| # | 环境 | 内核 | 架构 | 验证方式 | 验证内容 | 结果 |
|---|---|---|---|---|---|---|
| 1 | openKylin 2.0（容器） | — | x86_64 | CI: Project Build Test | openKylin 用户态环境下完整构建、二进制可执行 | 通过 |
| 2 | Ubuntu 24.04 | 6.1.x | x86_64 | CI: Kernel Matrix Test（virtme-ng） | BPF 程序加载/挂载 + hot/cpu/mem/lock 冒烟 | 通过 |
| 3 | Ubuntu 24.04 | 6.6.143 | x86_64 | CI: Kernel Matrix Test（virtme-ng） | 同上（openKylin 目标内核版本） | 通过 |
| 4 | Ubuntu 24.04 | 6.12.x | x86_64 | CI: Kernel Matrix Test（virtme-ng） | 同上 | 通过 |
| 5 | Ubuntu 24.04 | 6.17（azure） | ARM64 | CI: ARM64 Build Test | 原生构建 + 5 个子命令冒烟（真实加载 BPF） | 通过 |
| 6 | debian 13 | 6.12 | x86_64 | 本地开发实测 | 全部子命令 + 异常场景复现 | 通过 |
| 7 | openKylin 2.0（完整系统） | 6.6 | x86_64 | QEMU 实测 | 5 类异常场景注入与检出 | 计划中 |

> CI run 链接见仓库 Actions 页面对应 workflow 的最新记录。

## 验证方式说明

### CI: Project Build Test（`.github/workflows/build-test.yml`）

在 openKylin 2.0 基础镜像（`ghcr.io/x2002w/eebpf-build`）容器内完整构建，
验证 openKylin 用户态工具链与依赖（glibc、libbpf、LLVM 19）下的可构建性。

### CI: Kernel Matrix Test（`.github/workflows/kernel-matrix.yml`）

跨内核版本验证，核心是检验 CO-RE 重定位的实际效果：

- 宿主机（runner）上编译一次 `eebpf`，**同一个二进制**分别在 6.1 / 6.6 / 6.12 内核上运行
- 内核来自 `ghcr.io/cilium/ci-kernels`（cilium/ebpf 官方 CI 同款，已配置 BTF）
- virtme-ng + QEMU/KVM 引导目标内核，根文件系统共享宿主机
- 每个内核跑 `hot` / `cpu` / `mem` / `lock` 各 4 秒，验证 BPF 程序通过 verifier、
  tracepoint/kprobe 挂载成功、数据采集与报告输出正常
- `io` 子命令因 VM 内无真实块设备事件不在矩阵内，由本地实测覆盖

矩阵中 6.6 与 openKylin 2.0 内核版本一致，与第 1 行的用户态验证互补，
共同构成"openKylin 用户态 + openKylin 内核版本"的组合证据。

### CI: ARM64 Build Test（`.github/workflows/build-test-arm.yml`）

`ubuntu-24.04-arm` 原生 ARM64 runner 上构建并以 root 真实加载 BPF 程序，
验证跨架构可用性。系统调用号映射通过 `__NR_*` 宏在编译期自动适配架构
（x86_64 与 ARM64 的 asm-generic 编号不同）。

### 本地开发实测

debian 13 (内核 6.12) 物理机，配合 stress-ng / fio 注入 CPU、I/O、内存、
锁竞争、系统调用热点 5 类异常，验证检出与根因定位结论。

## 尚未覆盖

- **openKylin 完整系统**：容器验证的是用户态，openKylin 自身内核（6.6）上的
  完整系统实测计划以 QEMU 虚拟机进行（矩阵第 7 行）
- **RISC-V**：构建系统已支持（Makefile 架构探测 + `__NR_*` 宏适配），
  受 CI runner 与硬件条件限制暂无运行时验证
- **6.1 以下内核**：项目目标为 6.6+，6.1 实测可用但不作承诺；更老内核未验证
