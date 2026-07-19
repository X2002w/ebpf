#!/usr/bin/env python3
"""
采集系统级信息，供大模型在分析 eBPF 基础指标时结合硬件上下文做判断。
"""

import os
import re
from pathlib import Path

SYS_BLOCK = Path("/sys/block")
SYS_DEVICES = Path("/sys/devices/system/cpu")


# 通用工具 
def _read(path, default=""):
    try:
        return Path(path).read_text().strip()
    except (OSError, PermissionError):
        return default


def _read_int(path, default=0):
    try:
        s = _read(path)
        if not s:
            return default
        # handle suffixes like "32K", "6M"
        s = s.upper()
        mul = 1
        if s.endswith("K"):
            mul = 1024
            s = s[:-1]
        elif s.endswith("M"):
            mul = 1024 * 1024
            s = s[:-1]
        elif s.endswith("G"):
            mul = 1024 * 1024 * 1024
            s = s[:-1]
        return int(s) * mul
    except (ValueError, TypeError):
        return default


def _read_lines(path):
    try:
        return Path(path).read_text().strip().splitlines()
    except (OSError, PermissionError):
        return []


# 系统
def _os_release():
    info = {}
    for line in _read_lines("/etc/os-release"):
        if "=" in line:
            k, v = line.split("=", 1)
            v = v.strip('"')
            info[k] = v
    return info


def collect_system():
    os_info = _os_release()
    return {
        "hostname": _read("/proc/sys/kernel/hostname"),
        "kernel": _read("/proc/sys/kernel/osrelease"),
        # 读取发行版名称
        "os": os_info.get("PRETTY_NAME", os_info.get("NAME", "")),
        "arch": os.uname().machine,
    }


# CPU 

def collect_cpu():
    """从 /proc/cpuinfo 和 sysfs 提取 CPU 信息。"""
    cores = set()
    phys_ids = set()
    model = ""
    cpu_mhz = 0.0

    for line in _read_lines("/proc/cpuinfo"):
        line = line.strip()
        if line.startswith("model name"):
            model = line.split(":", 1)[1].strip()
        elif line.startswith("cpu cores"):
            cores.add(int(line.split(":", 1)[1].strip()))
        elif line.startswith("physical id"):
            phys_ids.add(int(line.split(":", 1)[1].strip()))
        elif line.startswith("cpu MHz"):
            try:
                cpu_mhz = float(line.split(":", 1)[1].strip())
            except ValueError:
                pass

    # 解析 lscpu 补充分数信息（如果可用）
    nr_sockets = len(phys_ids) if phys_ids else 1
    nr_cores = max(cores) if cores else os.cpu_count() or 0
    nr_threads = os.cpu_count() or 0

    # cache 信息 (sysfs 返回 "32K" 等格式，_read_int 解析后为字节，除以 1024 得 KB)
    l1d = _read_int("/sys/devices/system/cpu/cpu0/cache/index0/size", 0) // 1024
    l1i = _read_int("/sys/devices/system/cpu/cpu0/cache/index1/size", 0) // 1024
    l2 = _read_int("/sys/devices/system/cpu/cpu0/cache/index2/size", 0) // 1024
    l3 = _read_int("/sys/devices/system/cpu/cpu0/cache/index3/size", 0) // 1024

    # 频率
    base_freq = _read_int(
        "/sys/devices/system/cpu/cpu0/cpufreq/base_frequency", 0
    )
    max_freq = _read_int(
        "/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq", 0
    )

    return {
        "model": model,
        "sockets": nr_sockets,
        "physical_cores": nr_cores,
        "logical_cores": nr_threads,
        "base_freq_khz": base_freq // 1000 if base_freq else int(cpu_mhz),
        "max_freq_khz": max_freq // 1000 if max_freq else 0,
        "l1d_kb": l1d,
        "l1i_kb": l1i,
        "l2_kb": l2,
        "l3_kb": l3,
    }


# 内存 
def collect_memory():
    mem = {}
    for line in _read_lines("/proc/meminfo"):
        parts = line.split(":")
        if len(parts) == 2:
            key = parts[0].strip()
            val = parts[1].strip().split()[0]
            try:
                mem[key] = int(val)
            except ValueError:
                mem[key] = val

    total_kb = mem.get("MemTotal", 0)
    swap_kb = mem.get("SwapTotal", 0)
    dirty_ratio = _read_int("/proc/sys/vm/dirty_ratio")
    dirty_bg_ratio = _read_int("/proc/sys/vm/dirty_background_ratio")

    return {
        "total_gb": round(total_kb / 1024 / 1024, 1),
        "swap_gb": round(swap_kb / 1024 / 1024, 1),
        "dirty_ratio_pct": dirty_ratio,
        "dirty_background_ratio_pct": dirty_bg_ratio,
    }


# 磁盘 

# 常见磁盘型号关键词 → 类型推断
_SSD_KEYWORDS = [
    "ssd", "nvme", "solid state", "micron", "samsung evo",
    "samsung pro", "wd black sn", "wd blue sn", "kingston sa",
    "kingston skc", "intel ssd", "intel optane", "crucial ct",
    "sandisk sdss", "sandisk ultra", "toshiba ks", "toshiba xg",
    "sk hynix", "kioxia", "seagate firecuda 5", "pm9", "pm8",
    "adata", "team group", "pny cs", "sabrent", "corsair mp",
    "wd green sn", "wd red sn", "seagate barracuda 1", "patriot",
    "samsung 9", "micron 7", "kioxia exceria", "hynix gold p31",
]


def _is_rotational(dev_name):
    """0=SSD, 1=HDD"""
    return _read_int(SYS_BLOCK / dev_name / "queue" / "rotational", -1)


def _disk_model(dev_name):
    model = _read(SYS_BLOCK / dev_name / "device" / "model")
    if not model:
        model = _read(SYS_BLOCK / dev_name / "device" / "name")
    return model


def _disk_type(dev_name, model):
    """推断磁盘类型: NVMe / SSD / HDD"""
    n = dev_name.lower()
    m = model.lower()
    if "nvme" in n or "nvme" in m:
        return "NVMe"
    rot = _is_rotational(dev_name)
    if rot == 0:
        return "SSD"
    if rot == 1:
        return "HDD"
    # rot==-1 时 rotational 不可读（如 virtio），回落至型号关键词匹配
    for kw in _SSD_KEYWORDS:
        if kw in m:
            return "SSD"
    return "HDD"


def _disk_interface(dev_name):
    """从 sysfs 路径推断接口类型"""
    link = os.readlink(str(SYS_BLOCK / dev_name))
    if "nvme" in dev_name.lower():
        gen = _read(SYS_BLOCK / dev_name / "device" / "subsystem" /
                    dev_name / "pcie_link_speed", "")
        return f"NVMe ({gen})" if gen else "NVMe"
    if "usb" in link:
        return "USB"
    # 尝试读 host 编号判断 SATA/SAS
    host = re.search(r"host(\d+)", link)
    if host:
        return "SATA"
    return "unknown"


def _disk_speed_mbps(dev_name, disk_type, model):
    """根据磁盘类型和型号估算典型读写速率 (MB/s)，用于大模型参考。

    优先级: 1) smartctl/hdparm 实测  2) 型号数据库  3) 类型默认值
    """
    model_lower = model.lower()
    if disk_type == "NVMe":
        # Gen3 ~3500, Gen4 ~5000-7000
        gen = _read(SYS_BLOCK / dev_name / "device" / "subsystem" /
                    dev_name / "pcie_link_speed", "")
        if "16" in gen:   # Gen4 ≈ 16 GT/s
            return 5000
        return 3000
    if disk_type == "SSD":
        if "evo" in model_lower and "870" in model_lower:
            return 560   # Samsung 870 EVO
        return 500
    if disk_type == "HDD":
        rpm = 7200
        # 尝试从型号中提取转速
        for part in model.split():
            if part.isdigit() and len(part) == 4 and part.startswith(("54", "59", "72", "10")):
                rpm = int(part)
                break
        return 200 if rpm >= 10000 else 160 if rpm >= 7200 else 100
    return 200


def _disk_scheduler(dev_name):
    raw = _read(SYS_BLOCK / dev_name / "queue" / "scheduler")
    m = re.search(r"\[(.+?)\]", raw)
    return m.group(1) if m else raw


def collect_disks():
    disks = []
    for dev in sorted(SYS_BLOCK.iterdir()):
        name = dev.name
        # 跳过 loop/ram/dm 等虚拟设备
        if name.startswith(("loop", "ram", "dm-", "zram")):
            continue

        size_sectors = _read_int(SYS_BLOCK / name / "size", 0)
        if size_sectors == 0:
            continue

        model = _disk_model(name)
        dtype = _disk_type(name, model)
        qdepth = _read_int(SYS_BLOCK / name / "queue" / "nr_requests")
        sched = _disk_scheduler(name)
        sector_size = _read_int(SYS_BLOCK / name / "queue" / "hw_sector_size", 512)
        speed_mbps = _disk_speed_mbps(name, dtype, model)
        rotational = _is_rotational(name)

        dev_id = _read(SYS_BLOCK / name / "dev", "?:?")
        disks.append({
            "name": name,
            "major_minor": dev_id,
            "model": model,
            "type": dtype,
            "size_gb": round(size_sectors * 512 / 1e9, 1),
            "rotational": rotational,
            "queue_depth": qdepth,
            "scheduler": sched,
            "sector_size": sector_size,
            "interface": _disk_interface(name),
            "estimated_read_mbps": speed_mbps,
            "estimated_write_mbps": int(speed_mbps * (0.5 if dtype == "SSD" else 0.95)),
        })

    return disks


# 块设备附加信息 

def collect_block_stats():
    """读取 /sys/block/*/stat 补充设备级统计快照。"""
    stats = {}
    for dev in sorted(SYS_BLOCK.iterdir()):
        name = dev.name
        if name.startswith(("loop", "ram", "dm-", "zram")):
            continue
        raw = _read(SYS_BLOCK / name / "stat")
        if not raw:
            continue
        parts = raw.split()
        if len(parts) < 11:
            continue
        stats[name] = {
            "rd_ios": int(parts[0]),
            "rd_sectors": int(parts[2]),
            "wr_ios": int(parts[4]),
            "wr_sectors": int(parts[6]),
            "in_flight": int(parts[8]),
            "io_ticks": int(parts[9]),
            "time_in_queue": int(parts[10]),
        }
    return stats


# 汇总 
def collect_all():
    return {
        "system": collect_system(),
        "cpu": collect_cpu(),
        "memory": collect_memory(),
        "disks": collect_disks(),
        "block_stats_snapshot": collect_block_stats(),
    }


def to_text(data: dict) -> str:
    """将采集数据转换为纯文本，供 LLM 解析。"""
    s = data.get("system", {})
    c = data.get("cpu", {})
    m = data.get("memory", {})
    disks = data.get("disks", [])

    lines = [
        "# 当前系统基础信息",
        "",
        "## 系统环境信息",
        f"主机名: {s.get('hostname', '?')}",
        f"OS: {s.get('os', '?')}",
        f"内核: {s.get('kernel', '?')}",
        f"架构: {s.get('arch', '?')}",
        "",
        "## CPU",
        f"型号: {c.get('model', '?')}",
        f"插槽数: {c.get('sockets', '?')}  物理核: {c.get('physical_cores', '?')}  逻辑核: {c.get('logical_cores', '?')}",
        f"基频/最大频率: {c.get('base_freq_khz', '?')} / {c.get('max_freq_khz', '?')} MHz",
        f"L1d: {c.get('l1d_kb', '?')}KB  L1i: {c.get('l1i_kb', '?')}KB  L2: {c.get('l2_kb', '?')}KB  L3: {c.get('l3_kb', '?')}KB",
        "",
        "## 内存",
        f"总内存: {m.get('total_gb', '?')} GB  交换空间: {m.get('swap_gb', '?')} GB",
        f"脏页阈值: dirty_ratio={m.get('dirty_ratio_pct', '?')}%  dirty_bg_ratio={m.get('dirty_background_ratio_pct', '?')}%",
        "",
        "## 磁盘",
    ]

    for d in disks:
        lines.append(
            f"  {d.get('name', '?')} ({d.get('major_minor', '?')}): {d.get('model', '?')}  "
            f"类型={d.get('type', '?')}  "
            f"容量={d.get('size_gb', '?')}GB  "
            f"扇区={d.get('sector_size', '?')}B  "
            f"队列深度={d.get('queue_depth', '?')}  "
            f"调度器={d.get('scheduler', '?')}  "
            f"接口={d.get('interface', '?')}  "
            f"估算读速={d.get('estimated_read_mbps', '?')}MB/s  估算写速={d.get('estimated_write_mbps', '?')}MB/s"
        )

    return "\n".join(lines)


# CLI

def main():
    data = collect_all()
    print(to_text(data))


if __name__ == "__main__":
    main()
