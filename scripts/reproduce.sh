#!/bin/bash
# eebpf 场景复现与验证脚本 — 使用赛题参考命令注入异常，验证检测能力
# 用法: sudo ./scripts/reproduce.sh [输出目录，默认 report]

set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
OUT_DIR="${1:-$SCRIPT_DIR/report}"
EEBPF="$SCRIPT_DIR/eebpf"
SUMMARY="$OUT_DIR/demo_summary.md"

# 测试参数 — 缩短时长加快验证，可设环境变量覆盖
CPU_DUR="${CPU_DUR:-30}"
IO_DUR="${IO_DUR:-30}"
MEM_DUR="${MEM_DUR:-30}"
LOCK_DUR="${LOCK_DUR:-30}"
EEBPF_DUR="${EEBPF_DUR:-15}"

# fio 测试文件须落在真实块设备上 (tmpfs 不产生 I/O)
if [ -n "$SUDO_USER" ]; then
	REAL_HOME=$(getent passwd "$SUDO_USER" | cut -d: -f6)
	FIO_FILE="${FIO_FILE:-$REAL_HOME/fio-demo.img}"
else
	FIO_FILE="${FIO_FILE:-/tmp/fio-demo.img}"
fi
FIO_SIZE="${FIO_SIZE:-2G}"

mkdir -p "$OUT_DIR"

# 输出辅助
red()   { echo -e "\033[31m$*\033[0m"; }
green() { echo -e "\033[32m$*\033[0m"; }
bold()  { echo -e "\033[1m$*\033[0m"; }
dim()   { echo -e "\033[2m$*\033[0m"; }

# 依赖检查
check_deps() {
	local miss=""
	for cmd in stress-ng fio "$EEBPF"; do
		if ! command -v "$cmd" &>/dev/null && [ ! -x "$cmd" ]; then
			red "  缺失: $cmd"
			miss="$miss $cmd"
		fi
	done
	if [ -n "$miss" ]; then
		red "请先安装缺失依赖: apt install stress-ng fio"
		exit 1
	fi
	green "  依赖检查通过"
}

# 清理残留
cleanup() {
	killall stress-ng fio 2>/dev/null
	rm -f "$FIO_FILE"
}
trap cleanup EXIT

# 场景运行
run_scenario() {
	local name="$1"          # 场景名称
	local module="$2"        # eebpf 子命令
	local stress_cmd="$3"    # 注入命令
	local expected="$4"      # 期望根因关键词
	local setup_fn="$5"      # 前置准备（可选）

	echo ""
	bold "============================================================"
	bold "  场景: $name"
	bold "  模块: eebpf $module"
	bold "  期望: $expected"
	bold "============================================================"

	# 前置准备
	if [ -n "$setup_fn" ]; then
		dim "  前置准备..."
		eval "$setup_fn"
	fi

	# 启动注入
	dim "  启动注入负载..."
	eval "$stress_cmd" &
	local stress_pid=$!
	sleep 3

	# 运行 eebpf
	dim "  运行 eebpf $module -d $EEBPF_DUR ..."
	local json_file="$OUT_DIR/${module}_demo.json"
	local md_file="$OUT_DIR/${module}_demo.md"

	"$EEBPF" "$module" -j -d "$EEBPF_DUR" >/dev/null 2>&1

	# 停止注入
	dim "  停止注入负载..."
	kill $stress_pid 2>/dev/null
	wait $stress_pid 2>/dev/null
	killall stress-ng fio 2>/dev/null
	sleep 1

	# 收集报告
	local json_src=""
	case "$module" in
		cpu)  json_src="report/cpu.json" ;;
		io)   json_src="report/io.json" ;;
		mem)  json_src="report/mem.json" ;;
		lock) json_src="report/lock.json" ;;
		hot)  json_src="report/hot.json" ;;
	esac

	if [ -f "$json_src" ]; then
		cp "$json_src" "$json_file"
		local subtype=$(python3 -c "
import json, sys
with open('$json_src') as f:
    data = json.load(f)
for sec in data.get('sections', []):
    if sec.get('type') == 'diagnosis':
        for f in sec.get('findings', []):
            t = f.get('subtype', '')
            r = f.get('root_cause', '')
            if t and t != '正常':
                print(f'{t} | {r}')
                sys.exit(0)
print('正常 | 未检测到异常')
" 2>/dev/null)

		local anomaly_count=$(python3 -c "
import json
with open('$json_src') as f:
    data = json.load(f)
count = 0
for sec in data.get('sections', []):
    if sec.get('type') == 'diagnosis':
        for f in sec.get('findings', []):
            if f.get('is_anomaly'):
                count += 1
print(count)
" 2>/dev/null)

		if [ -z "$subtype" ]; then
			subtype="(解析失败)"
			anomaly_count="?"
		fi

		# 判断是否命中期望
		local match="✗"
		if echo "$subtype" | grep -qi "$expected"; then
			match="✓"
		fi

		green "  检测结果: $subtype"
		green "  异常数: $anomaly_count  匹配期望: $match"
		echo "| $name | $module | \`$subtype\` | $anomaly_count | $match |" >> "$SUMMARY"
	else
		red "  报告未生成: $json_src"
		echo "| $name | $module | (报告缺失) | - | ✗ |" >> "$SUMMARY"
	fi
}

# ================================================================

echo ""
bold "eebpf 场景复现与验证"
bold "输出目录: $OUT_DIR"
echo ""

# Root 检查
if [ "$(id -u)" != "0" ]; then
	red "请使用 root 权限运行: sudo ./scripts/reproduce.sh"
	exit 1
fi

echo "[1/5] 依赖检查"
check_deps

# 初始化汇总表
cat > "$SUMMARY" << 'EOF'
# eebpf 场景复现验证报告

EOF

echo "**测试时间**: $(date '+%Y-%m-%d %H:%M:%S')" >> "$SUMMARY"
echo "**内核版本**: $(uname -r)" >> "$SUMMARY"
echo "**架构**: $(uname -m)" >> "$SUMMARY"
echo "" >> "$SUMMARY"
echo "## 场景验证结果" >> "$SUMMARY"
echo "" >> "$SUMMARY"
echo "| 场景 | 模块 | 检测结果 | 异常数 | 匹配期望 |" >> "$SUMMARY"
echo "|------|------|----------|--------|----------|" >> "$SUMMARY"

# ================================================================
echo ""
echo "[2/5] CPU 异常 — stress-ng CPU 密集计算"
run_scenario "CPU 密集计算" "cpu" \
	"stress-ng --cpu 4 --cpu-method matrixprod --timeout ${CPU_DUR}s --metrics-brief" \
	"CPU 密集"

# ================================================================
echo ""
echo "[3/5] I/O 异常 — fio 随机读写"
run_scenario "I/O 随机读写抖动" "io" \
	"fio --name=randrw --filename=$FIO_FILE --size=$FIO_SIZE --rw=randrw --rwmixread=70 --bs=4k --iodepth=64 --numjobs=4 --runtime=${IO_DUR} --time_based --group_reporting --direct=1 --ioengine=libaio" \
	"I/O" \
	"rm -f $FIO_FILE"

# ================================================================
echo ""
echo "[4/5] 内存异常 — stress-ng 内存压力"
run_scenario "内存压力与抖动" "mem" \
	"stress-ng --vm 4 --vm-bytes 256M --vm-keep --timeout ${MEM_DUR}s --metrics-brief" \
	"内存"

# ================================================================
echo ""
echo "[5/5] 锁竞争 — stress-ng mutex 争用"
run_scenario "futex 锁竞争" "lock" \
	"stress-ng --mutex 8 --timeout ${LOCK_DUR}s --metrics-brief" \
	"锁竞争"

# ================================================================
# 结果汇总
cat >> "$SUMMARY" << EOF

## 期望 vs 实际根因对照

| 场景 | 注入方式 | 期望根因 | 实际输出 |
|------|----------|----------|----------|
| CPU | stress-ng --cpu 4 matrixprod | CPU 密集型计算 | 见上方验证表 |
| I/O | fio randrw iodepth=64 | I/O 延迟抖动/队列拥堵 | 见上方验证表 |
| 内存 | stress-ng --vm 4 80% | 内存抖动/回收压力 | 见上方验证表 |
| 锁 | stress-ng --mutex 8 | 锁竞争/futex 等待 | 见上方验证表 |

## 输出文件

| 文件 | 说明 |
|------|------|
| $OUT_DIR/cpu_demo.json | CPU 场景 JSON 报告 |
| $OUT_DIR/io_demo.json | I/O 场景 JSON 报告 |
| $OUT_DIR/mem_demo.json | 内存场景 JSON 报告 |
| $OUT_DIR/lock_demo.json | 锁竞争场景 JSON 报告 |
| $SUMMARY | 本汇总报告 |

> 使用方法:
> \`\`\`bash
> sudo ./scripts/reproduce.sh          # 默认输出到 report/
> sudo ./scripts/reproduce.sh /tmp/out  # 自定义输出目录
> \`\`\`
>
> 环境变量:
> - \`CPU_DUR\`, \`IO_DUR\`, \`MEM_DUR\`, \`LOCK_DUR\`: 各场景注入时长 (默认 30s)
> - \`EEBPF_DUR\`: eebpf 采样时长 (默认 15s)
> - \`FIO_FILE\`, \`FIO_SIZE\`: fio 测试文件路径和大小
EOF

echo ""
bold "============================================================"
bold "  验证完成"
bold "  汇总报告: $SUMMARY"
bold "  JSON 报告: $OUT_DIR/"
bold "============================================================"
