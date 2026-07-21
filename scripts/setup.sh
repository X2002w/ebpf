#!/bin/bash
# eebpf 一键部署与验证 — 安装依赖 -> 构建 -> 场景复现
# 用法: ./scripts/setup.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$SCRIPT_DIR"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BOLD='\033[1m'
NC='\033[0m'

step()  { echo -e "\n${BOLD}[$1/$TOTAL] $2${NC}"; }
ok()    { echo -e "  ${GREEN}[OK]${NC} $1"; }
warn()  { echo -e "  ${YELLOW}[!]${NC} $1"; }
die()   { echo -e "  ${RED}[FATAL]${NC} $1"; exit 1; }

# 步骤计数
TOTAL=4

echo ""
echo -e "${BOLD}eebpf 一键部署与验证${NC}"
echo ""

step 1 "环境依赖检查与安装"

if [ -x "$SCRIPT_DIR/start.sh" ]; then
	bash "$SCRIPT_DIR/start.sh"
else
	warn "start.sh 未找到，跳过依赖检查"
fi

step 2 "构建 eebpf"

make clean >/dev/null 2>&1 || true
if make -j"$(nproc)"; then
	ok "eebpf 构建成功 → $SCRIPT_DIR/eebpf"
else
	die "构建失败，请检查依赖是否安装完整"
fi

step 3 "验证 eebpf 可执行"

for mod in cpu io mem lock hot; do
	if "$SCRIPT_DIR/eebpf" "$mod" -h >/dev/null 2>&1; then
		ok "eebpf $mod"
	else
		warn "eebpf $mod 帮助输出异常"
	fi
done

step 4 "场景复现测试"

if [ "$(id -u)" = "0" ]; then
	if [ -x "$SCRIPT_DIR/scripts/reproduce.sh" ]; then
		bash "$SCRIPT_DIR/scripts/reproduce.sh"
	else
		warn "reproduce.sh 未找到，跳过场景测试"
	fi
else
	warn "非 root 用户，跳过场景复现测试"
	echo "  请以 root 运行场景测试: sudo ./scripts/reproduce.sh"
fi

echo ""
echo -e "${BOLD}============================================================${NC}"
echo -e "${BOLD}  部署完成${NC}"
echo ""
echo "  二进制文件:  $SCRIPT_DIR/eebpf"
echo "  场景测试:    sudo ./scripts/reproduce.sh"
echo "  AI 诊断:     source ai_analysis/venv/bin/activate"
echo "               python3 ai_analysis/caller.py report/ -m cpu,io,mem,lock,hot"
echo ""
echo "  使用示例:"
echo "    sudo ./eebpf cpu -d 10"
echo "    sudo ./eebpf io  -d 10"
echo "    sudo ./eebpf mem -d 10"
echo "    sudo ./eebpf lock -d 10"
echo "    sudo ./eebpf hot -d 10"
echo -e "${BOLD}============================================================${NC}"
