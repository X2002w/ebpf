#!/bin/bash
# eebpf 性能基准测试 — 测量 CPU/内存/时延/吞吐 四项开销
# help: sudo ./scripts/bench.sh [输出目录，默认 report]

# 获取路径
# 安全获取脚本所在目录
script_path="$0"
script_dir="$(dirname "$script_path")"
if [ "$script_dir" = "." ]; then
	script_dir="$(pwd)"
fi
SCRIPT_DIR="$(cd "$script_dir/.." && pwd)"
REPORT_DIR="${1:-$SCRIPT_DIR/report}"
OUTPUT="$REPORT_DIR/benchmark.md"
EEBPF="$SCRIPT_DIR/eebpf"
TEST_DUR=12
FIO_FILE="${FIO_FILE:-/tmp/eebpf-bench.img}"
FIO_SIZE="${FIO_SIZE:-512M}"

mkdir -p "$REPORT_DIR"

# 输出辅助
red()   { echo -e "\033[31m$*\033[0m"; }
green() { echo -e "\033[32m$*\033[0m"; }
dim()   { echo -e "\033[2m$*\033[0m"; }
die()   { red "FATAL: $*"; exit 1; }

# 依赖检查
check_deps() {
	local miss=""
	for t in stress-ng fio bc python3; do
		command -v "$t" &>/dev/null || miss="$miss $t"
	done
	if [ -n "$miss" ]; then
		die "缺少依赖:$miss"
	fi
	if [ ! -x "$EEBPF" ]; then
		die "未找到 eebpf 二进制 ($EEBPF)，请先 make"
	fi
}

# bc 浮点比较，条件成立输出 1 否则 0
bc_cmp() { echo "$1" | bc -l 2>/dev/null || echo 0; }

# CPU tick 快照
cpu_ticks() {
	awk '/^cpu /{print $2,$3,$4,$5}' /proc/stat
}

# 两次快照间 CPU 使用率 (%)
cpu_pct() {
	local u1=$1 n1=$2 s1=$3 i1=$4 u2=$5 n2=$6 s2=$7 i2=$8
	local t1=$((u1+n1+s1+i1))
	local t2=$((u2+n2+s2+i2))
	local dt=$((t2-t1))
	local di=$((i2-i1))
	if [ "$dt" -le 0 ]; then
		echo "0"
		return
	fi
	echo "scale=2; 100*(1 - $di/$dt)" | bc
}

# 确保 fio 测试文件存在 
ensure_fio_file() {
	if [ ! -f "$FIO_FILE" ]; then
		dim "创建测试文件 $FIO_FILE ($FIO_SIZE)..."
		dd if=/dev/zero of="$FIO_FILE" bs=1M count="${FIO_SIZE//M/}" 2>/dev/null
	fi
}

# 1. CPU 开销
bench_cpu() {
	echo ""
	echo "=== CPU 开销测试 ==============================================="

	local dur=$TEST_DUR

	# baseline 
	dim "baseline: stress-ng 运行中..."
	stress-ng --cpu 2 --timeout $((dur+5))s &>/dev/null &
	local spid=$!
	sleep 2

	local ticks1
	ticks1=$(cpu_ticks)
	if [ -z "$ticks1" ]; then
		red "无法读取 /proc/stat"; return 1
	fi
	read b_u b_n b_s b_i <<< "$ticks1"
	sleep "$dur"
	local ticks2
	ticks2=$(cpu_ticks)
	read b_u2 b_n2 b_s2 b_i2 <<< "$ticks2"
	wait $spid 2>/dev/null

	local BASE_CPU
	BASE_CPU=$(cpu_pct $b_u $b_n $b_s $b_i $b_u2 $b_n2 $b_s2 $b_i2)
	echo "  baseline 系统 CPU: ${BASE_CPU}%"

	# with eebpf 
	dim "对比: stress-ng + eebpf 运行中..."
	stress-ng --cpu 2 --timeout $((dur+5))s &>/dev/null &
	spid=$!
	sleep 2

	"$EEBPF" cpu -d "$dur" -p 0 &>/dev/null &
	local epid=$!
	sleep 1

	ticks1=$(cpu_ticks)
	read e_u e_n e_s e_i <<< "$ticks1"
	sleep "$dur"
	ticks2=$(cpu_ticks)
	read e_u2 e_n2 e_s2 e_i2 <<< "$ticks2"

	local EBPF_CPU
	EBPF_CPU=$(cpu_pct $e_u $e_n $e_s $e_i $e_u2 $e_n2 $e_s2 $e_i2)

	wait $spid 2>/dev/null
	wait $epid 2>/dev/null

	local CPU_DELTA
	CPU_DELTA=$(echo "scale=2; $EBPF_CPU - $BASE_CPU" | bc)
	echo "  with_eebpf 系统 CPU: ${EBPF_CPU}%"
	echo "  CPU 增量: +${CPU_DELTA}%"

	# 评估
	local verdict="可忽略"
	if [ "$(bc_cmp "$CPU_DELTA > 5")" = "1" ]; then
		verdict="需优化"
	elif [ "$(bc_cmp "$CPU_DELTA > 2")" = "1" ]; then
		verdict="轻微"
	fi
	echo "  评估: [$verdict]"

	# 保存结果
	CPU_RESULT="| 系统 CPU 增量 | ${BASE_CPU}% | ${EBPF_CPU}% | +${CPU_DELTA}% | $verdict |"
	CPU_SELF_RESULT="| eebpf 进程 CPU | - | - | - | 见下方说明 |"
}

# 2. 内存开销
bench_mem() {
	echo ""
	echo "=== 内存开销测试 ==============================================="

	local dur=$TEST_DUR

	dim "启动 eebpf cpu -d $dur 并采样内存..."
	"$EEBPF" cpu -d "$dur" -p 0 &>/dev/null &
	local epid=$!
	sleep 1

	# 采样 RSS 峰值
	local rss_peak=0 rss_kb
	while kill -0 $epid 2>/dev/null; do
		rss_kb=$(awk '/VmRSS/{print $2}' /proc/$epid/status 2>/dev/null || echo 0)
		if [ "$rss_kb" -gt "$rss_peak" ] 2>/dev/null; then
			rss_peak=$rss_kb
		fi
		sleep 0.3
	done
	wait $epid 2>/dev/null

	local RSS_MB
	RSS_MB=$(echo "scale=1; $rss_peak / 1024" | bc)
	echo "  RSS 峰值: ${RSS_MB} MB"

	# BPF map 内存
	local map_kb=0
	if command -v bpftool &>/dev/null; then
		"$EEBPF" cpu -d 3 -p 0 &>/dev/null &
		epid=$!
		sleep 1
		map_kb=$(bpftool map list -j 2>/dev/null | python3 -c "
import json,sys
try:
  data=json.load(sys.stdin)
  total=sum(m.get('bytes_memlock',0) for m in data)
  print(total//1024)
except: print(0)
" 2>/dev/null || echo 0)
		wait $epid 2>/dev/null
	fi

	local MAP_MB
	MAP_MB=$(echo "scale=1; $map_kb / 1024" | bc)
	local TOTAL_MB
	TOTAL_MB=$(echo "scale=1; ($rss_peak + $map_kb) / 1024" | bc)
	echo "  BPF map: ${MAP_MB} MB"
	echo "  合计: ${TOTAL_MB} MB"

	local verdict="极低"
	if [ "${TOTAL_MB%.*}" -gt 50 ] 2>/dev/null; then
		verdict="一般"
	fi

	MEM_RSS="| 进程 RSS | - | ${RSS_MB} MB | - | $verdict |"
	MEM_MAP="| BPF map 锁定内存 | - | ${MAP_MB} MB | - | - |"
}

# 3. I/O 时延影响
bench_latency() {
	echo ""
	echo "=== I/O 时延测试 ==============================================="

	ensure_fio_file

	dim "baseline: fio randread (iodepth=1)..."
	local base_avg base_p99
	local BASE_JSON
	BASE_JSON=$(fio --name=lat --filename="$FIO_FILE" --rw=randread --bs=4k \
		--iodepth=1 --ioengine=sync --runtime="$TEST_DUR" --time_based \
		--direct=1 --output-format=json 2>/dev/null)

	base_avg=$(echo "$BASE_JSON" | python3 -c "
import json,sys
d=json.load(sys.stdin)['jobs'][0]['read']
print(d['clat_ns']['mean']//1000)
" 2>/dev/null || echo 0)

	base_p99=$(echo "$BASE_JSON" | python3 -c "
import json,sys
d=json.load(sys.stdin)['jobs'][0]['read']
print(d['clat_ns']['percentile']['99.000000']//1000)
" 2>/dev/null || echo 0)

	echo "  baseline: avg=${base_avg}us  p99=${base_p99}us"

	# with eebpf
	dim "对比: fio + eebpf io..."
	"$EEBPF" io -d "$TEST_DUR" &>/dev/null &
	local epid=$!
	sleep 1

	local EBPF_JSON
	EBPF_JSON=$(fio --name=lat --filename="$FIO_FILE" --rw=randread --bs=4k \
		--iodepth=1 --ioengine=sync --runtime="$TEST_DUR" --time_based \
		--direct=1 --output-format=json 2>/dev/null)
	wait $epid 2>/dev/null

	local ebpf_avg ebpf_p99
	ebpf_avg=$(echo "$EBPF_JSON" | python3 -c "
import json,sys
d=json.load(sys.stdin)['jobs'][0]['read']
print(d['clat_ns']['mean']//1000)
" 2>/dev/null || echo 0)

	ebpf_p99=$(echo "$EBPF_JSON" | python3 -c "
import json,sys
d=json.load(sys.stdin)['jobs'][0]['read']
print(d['clat_ns']['percentile']['99.000000']//1000)
" 2>/dev/null || echo 0)

	# P99 相对变化
	local p99_delta="N/A"
	local p99_verdict="可忽略"
	if [ "$base_p99" -gt 0 ] 2>/dev/null && [ "$ebpf_p99" -gt 0 ] 2>/dev/null; then
		p99_delta=$(echo "scale=1; 100 * ($ebpf_p99 - $base_p99) / $base_p99" | bc)
		if [ "$(bc_cmp "$p99_delta > 30")" = "1" ]; then
			p99_verdict="需优化"
		elif [ "$(bc_cmp "$p99_delta > 10")" = "1" ]; then
			p99_verdict="轻微"
		fi
	fi

	# 平均时延相对变化
	local avg_delta="N/A"
	if [ "$base_avg" -gt 0 ] 2>/dev/null && [ "$ebpf_avg" -gt 0 ] 2>/dev/null; then
		avg_delta=$(echo "scale=1; 100 * ($ebpf_avg - $base_avg) / $base_avg" | bc)
	fi

	echo "  with_eebpf: avg=${ebpf_avg}us  p99=${ebpf_p99}us"
	echo "  P99 delta: ${p99_delta}%  [$p99_verdict]"

	LAT_AVG="| I/O 平均时延 | ${base_avg} μs | ${ebpf_avg} μs | ${avg_delta}% | - |"
	LAT_P99="| I/O P99 时延 | ${base_p99} μs | ${ebpf_p99} μs | ${p99_delta}% | $p99_verdict |"
}

# 4. I/O 吞吐影响
bench_throughput() {
	echo ""
	echo "=== I/O 吞吐测试 ==============================================="

	ensure_fio_file

	dim "baseline: fio randread (iodepth=32, numjobs=4)..."
	local BASE_JSON
	BASE_JSON=$(fio --name=tp --filename="$FIO_FILE" --rw=randread --bs=4k \
		--iodepth=32 --numjobs=4 --ioengine=libaio \
		--runtime="$TEST_DUR" --time_based --direct=1 \
		--output-format=json 2>/dev/null)

	local base_iops base_bw
	base_iops=$(echo "$BASE_JSON" | python3 -c "
import json,sys
d=json.load(sys.stdin)['jobs'][0]['read']
print(int(d['iops']))
" 2>/dev/null || echo 0)

	base_bw=$(echo "$BASE_JSON" | python3 -c "
import json,sys
d=json.load(sys.stdin)['jobs'][0]['read']
print(int(d['bw_bytes']))
" 2>/dev/null || echo 0)

	local base_bw_mb
	base_bw_mb=$(echo "scale=1; $base_bw / 1048576" | bc)
	echo "  baseline: IOPS=$base_iops  吞吐=${base_bw_mb} MB/s"

	# with eebpf
	dim "对比: fio + eebpf io..."
	"$EEBPF" io -d "$TEST_DUR" &>/dev/null &
	local epid=$!
	sleep 1

	local EBPF_JSON
	EBPF_JSON=$(fio --name=tp --filename="$FIO_FILE" --rw=randread --bs=4k \
		--iodepth=32 --numjobs=4 --ioengine=libaio \
		--runtime="$TEST_DUR" --time_based --direct=1 \
		--output-format=json 2>/dev/null)
	wait $epid 2>/dev/null

	local ebpf_iops ebpf_bw
	ebpf_iops=$(echo "$EBPF_JSON" | python3 -c "
import json,sys
d=json.load(sys.stdin)['jobs'][0]['read']
print(int(d['iops']))
" 2>/dev/null || echo 0)

	ebpf_bw=$(echo "$EBPF_JSON" | python3 -c "
import json,sys
d=json.load(sys.stdin)['jobs'][0]['read']
print(int(d['bw_bytes']))
" 2>/dev/null || echo 0)

	local ebpf_bw_mb
	ebpf_bw_mb=$(echo "scale=1; $ebpf_bw / 1048576" | bc)

	# IOPS 相对变化
	local iops_delta="N/A"
	local iops_verdict="可忽略"
	if [ "${base_iops%.*}" -gt 0 ] 2>/dev/null && [ "${ebpf_iops%.*}" -gt 0 ] 2>/dev/null; then
		iops_delta=$(echo "scale=1; 100 * ($ebpf_iops - $base_iops) / $base_iops" | bc)
		if [ "$(bc_cmp "$iops_delta < -15")" = "1" ]; then
			iops_verdict="需优化"
		elif [ "$(bc_cmp "$iops_delta < -5")" = "1" ]; then
			iops_verdict="轻微"
		fi
	fi

	echo "  with_eebpf: IOPS=$ebpf_iops  吞吐=${ebpf_bw_mb} MB/s"
	echo "  IOPS delta: ${iops_delta}%  [$iops_verdict]"

	TP_IOPS="| IOPS | ${base_iops%.*} | ${ebpf_iops%.*} | ${iops_delta}% | $iops_verdict |"
	TP_BW="| 吞吐量 | ${base_bw_mb} MB/s | ${ebpf_bw_mb} MB/s | - | - |"
}

# 生成 Markdown 报告
gen_report() {
	local ts kernel arch
	ts=$(date '+%Y-%m-%d %H:%M:%S')
	kernel=$(uname -r)
	arch=$(uname -m)

	cat > "$OUTPUT" << ENDMD
# eebpf 性能基准测试报告

**测试时间**: $ts
**内核版本**: $kernel
**架构**: $arch
**测试时长** (每轮): ${TEST_DUR}s
**fio 测试文件**: $FIO_FILE ($FIO_SIZE)

---

## 汇总

| 指标 | 基线 (无 eebpf) | 有 eebpf | 变化 | 评估 |
|------|:--------------:|:--------:|:----:|:----:|
$CPU_RESULT
$CPU_SELF_RESULT
$MEM_RSS
$MEM_MAP
$LAT_AVG
$LAT_P99
$TP_IOPS
$TP_BW

> 说明:
> - **系统 CPU 增量**: /proc/stat 整体 CPU 使用率差值，含 BPF 程序在内核态的开销
> - **eebpf 进程 CPU**: 用户态采样汇总线程的 CPU 占比，短时运行(<1%)可忽略
> - **进程 RSS**: 含 BPF skeleton、JSON 构建缓冲区、libbpf 运行时
> - **BPF map**: 内核侧锁定内存，从 bpftool map list bytes_memlock 汇总

---

## 测试方法

### CPU 开销
- 负载: \`stress-ng --cpu 2\`
- 指标: /proc/stat 系统 CPU 使用率差值
- eebpf: \`eebpf cpu -d ${TEST_DUR} -p 0\`

### 内存开销
- 指标: /proc/<pid>/status VmRSS 峰值 + bpftool map bytes_memlock
- eebpf: \`eebpf cpu -d ${TEST_DUR} -p 0\`

### I/O 时延
- 负载: \`fio randread bs=4k iodepth=1 ioengine=sync\`
- 指标: fio clat_ns P99 / mean
- eebpf: \`eebpf io -d ${TEST_DUR}\`

### I/O 吞吐
- 负载: \`fio randread bs=4k iodepth=32 numjobs=4 ioengine=libaio\`
- 指标: fio IOPS / BW
- eebpf: \`eebpf io -d ${TEST_DUR}\`
ENDMD

	green "报告已生成: $OUTPUT"
}

main
# 主程序
main() {
	echo "============================================="
	echo " eebpf 性能基准测试"
	echo " 测试时长: ${TEST_DUR}s/轮"
	echo "============================================="

	check_deps

	if [ "$(id -u)" -ne 0 ]; then
		die "需要 root 权限运行 eebpf"
	fi

	bench_cpu    || red "CPU 测试失败，跳过"
	bench_mem    || red "内存测试失败，跳过"
	bench_latency   || red "时延测试失败，跳过"
	bench_throughput || red "吞吐测试失败，跳过"

	if [ -z "${CPU_RESULT:-}" ]; then
		red "所有测试均失败，未生成报告"
		exit 1
	fi

	gen_report

	echo ""
	green "全部完成。"
}

main
