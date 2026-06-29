#!/bin/bash
set -euo pipefail

# 颜色
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

PASS=0
FAIL=0

check_pass() { echo -e "  ${GREEN}[OK]${NC} $1"; PASS=$((PASS + 1)); }
check_fail() { echo -e "  ${RED}[FAIL]${NC} $1"; FAIL=$((FAIL + 1)); }

# 尝试安装并重新检查，返回 0=安装成功, 1=仍失败
try_install() {
    local pkg="$1"
    local check_cmd="$2"
    local label="$3"
    echo -e "  ${YELLOW}[...]${NC} 尝试安装 $pkg ..."
    if sudo apt install -y "$pkg" >/dev/null 2>&1; then
        if eval "$check_cmd"; then
            check_pass "$label"
            return 0
        fi
    fi
    check_fail "$label 安装失败"
    return 1
}

echo " -------------------------- "
echo " eBPF 项目依赖检查:"

# 命令行工具
for tool in clang make; do
    tpath=$(command -v "$tool" 2>/dev/null || true)
    if [ -n "$tpath" ]; then
        check_pass "$tool → $tpath"
    else
        try_install "$tool" "command -v $tool >/dev/null 2>&1" "$tool → \$(command -v $tool)"
    fi
done

# bpftool — 路径特殊，单独处理
bpftool_path=""
for p in /usr/sbin/bpftool /sbin/bpftool; do
    [ -x "$p" ] && { bpftool_path="$p"; break; }
done
if [ -z "$bpftool_path" ]; then
    bpftool_path=$(command -v bpftool 2>/dev/null || true)
fi
if [ -n "$bpftool_path" ]; then
    check_pass "bpftool → $bpftool_path"
else
    try_install "bpftool" '[ -x /usr/sbin/bpftool ] || [ -x /sbin/bpftool ] || command -v bpftool >/dev/null 2>&1' "bpftool → /usr/sbin/bpftool"
fi

# 运行时库
echo ""
echo " 运行时库:"

if find /usr/lib -maxdepth 4 -name "libbpf.so*" 2>/dev/null | grep -q .; then
    check_pass "libbpf"
else
    try_install "libbpf-dev" 'find /usr/lib -maxdepth 4 -name "libbpf.so*" 2>/dev/null | grep -q .' "libbpf"
fi

if find /usr/lib -maxdepth 4 -name "libelf.so*" 2>/dev/null | grep -q .; then
    check_pass "libelf"
else
    try_install "libelf-dev" 'find /usr/lib -maxdepth 4 -name "libelf.so*" 2>/dev/null | grep -q .' "libelf"
fi

if find /usr/lib -maxdepth 4 -name "libz.so*" 2>/dev/null | grep -q .; then
    check_pass "zlib"
else
    try_install "zlib1g-dev" 'find /usr/lib -maxdepth 4 -name "libz.so*" 2>/dev/null | grep -q .' "zlib"
fi

# 压力测试工具
echo ""
echo " 压力测试工具:"

for tool in stress-ng fio; do
    tpath=$(command -v "$tool" 2>/dev/null || true)
    if [ -n "$tpath" ]; then
        check_pass "$tool → $tpath"
    else
        try_install "$tool" "command -v $tool >/dev/null 2>&1" "$tool → \$(command -v $tool)"
    fi
done

# 统计检查结果
echo ""
echo "----------------------------------------"
echo " 检查完毕: 通过 ${PASS}, 失败 ${FAIL}"

if [ "$FAIL" -gt 0 ]; then
    echo ""
    echo -e "${RED}仍有缺失的依赖，请手动检查并安装。${NC}"
fi
