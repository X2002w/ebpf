#!/bin/bash
set -euo pipefail

# 颜色
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

PASS=0
FAIL=0

check_pass() { echo -e "  ${GREEN}[OK]${NC} $1"; PASS=$((PASS + 1)); }
check_fail() { echo -e "  ${RED}[FAIL]${NC} $1"; FAIL=$((FAIL + 1)); }

echo " -------------------------- "
echo " eBPF 项目依赖检查:"

# 命令行工具
for tool in clang make bpftool; do
    tpath=$(command -v "$tool" 2>/dev/null || true)
    # bpftool 通常装在 /usr/sbin，非 root PATH 不包含
    if [ -z "$tpath" ] && [ "$tool" = "bpftool" ]; then
        for p in /usr/sbin/bpftool /sbin/bpftool; do
            [ -x "$p" ] && { tpath="$p"; break; }
        done
    fi
    if [ -n "$tpath" ]; then
        check_pass "$tool → $tpath"
    else
        check_fail "$tool 未安装"
    fi
done

# 运行时库
# 直接查找 .so 文件，避免 ldconfig 缓存为空的兼容性问题
has_lib() {
    find /usr/lib -maxdepth 4 -name "$1" 2>/dev/null | grep -q .
}

if has_lib "libbpf.so*"; then
    check_pass "libbpf"
else
    check_fail "libbpf 未安装 (apt install libbpf-dev)"
fi

if has_lib "libelf.so*"; then
    check_pass "libelf"
else
    check_fail "libelf 未安装 (apt install libelf-dev)"
fi

if has_lib "libz.so*"; then
    check_pass "zlib"
else
    check_fail "zlib 未安装 (apt install zlib1g-dev)"
fi

# 压力测试工具
echo ""
echo " 压力测试工具:"

for tool in stress-ng fio; do
    tpath=$(command -v "$tool" 2>/dev/null || true)
    if [ -n "$tpath" ]; then
        check_pass "$tool → $tpath"
    else
        check_fail "$tool 未安装 (apt install $tool)"
    fi
done

# 统计检查结果
echo ""
echo "----------------------------------------"
echo " 检查完毕: 通过 ${PASS}, 失败 ${FAIL}"

if [ "$FAIL" -gt 0 ]; then
    echo ""
    echo -e "${RED}存在缺失的依赖，请安装:${NC}"
    echo "  sudo apt install -y clang libbpf-dev libelf-dev zlib1g-dev make bpftool stress-ng"
fi
