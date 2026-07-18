#!/bin/bash
# 检查 ai_analysis 运行环境是否就绪

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
AI_DIR="$PROJECT_DIR/ai_analysis"
REPORT_DIR="$PROJECT_DIR/report"
PASS=0
FAIL=0

check() {
	local label="$1"; shift
	if "$@" >/dev/null 2>&1; then
		echo "  [OK] $label"
		PASS=$((PASS + 1))
	else
		echo "  [FAIL] $label"
		FAIL=$((FAIL + 1))
	fi
}

echo "=== eBPF AI 诊断运行环境检查 ==="
echo ""

echo "[1] 基础环境"
check "python3 >= 3.10" python3 -c "import sys; assert sys.version_info >= (3,10)"
check "pip3 可用" python3 -m pip --version
echo ""

echo "[2] Python 依赖"
OPENAI_OK=false
if [ -f "$AI_DIR/venv/bin/python" ]; then
	if "$AI_DIR/venv/bin/python" -c "import openai" 2>/dev/null; then
		echo "  [OK] openai 已安装 (venv)"
		OPENAI_OK=true
		PASS=$((PASS + 1))
	fi
fi
if [ "$OPENAI_OK" = false ]; then
	if python3 -c "import openai" 2>/dev/null; then
		echo "  [OK] openai 已安装 (系统)"
		PASS=$((PASS + 1))
	else
		echo "  [FAIL] openai 未安装, 运行: pip install -r requirements.txt"
		FAIL=$((FAIL + 1))
	fi
fi
echo ""

echo "[3] API 配置"
check "api_config.json 存在" test -f "$AI_DIR/api_config.json"
check "api.txt 存在 (本地 key)" test -f "$AI_DIR/api.txt"
KEY_OK=false
if [ -f "$AI_DIR/api.txt" ]; then
	KEY=$(cat "$AI_DIR/api.txt" | tr -d '[:space:]')
	if [ -n "$KEY" ] && [ "$KEY" != "sk-xxxxxxxx" ]; then
		echo "  [OK] api.txt 有有效 key"
		KEY_OK=true
		((PASS++))
	fi
fi
if [ "$KEY_OK" = false ] && [ -n "$DEEPSEEK_API_KEY" ]; then
	echo "  [OK] 使用环境变量 DEEPSEEK_API_KEY"
	((PASS++))
elif [ "$KEY_OK" = false ]; then
	echo "  [WARN] 未检测到有效 API key (可设置 DEEPSEEK_API_KEY 或编辑 api.txt)"
fi
echo ""

echo "[4] 系统信息采集"
PYTHON=$(command -v python3)
[ -f "$AI_DIR/venv/bin/python" ] && PYTHON="$AI_DIR/venv/bin/python"
check "sys_message.py 可导入" "$PYTHON" -c "import sys; sys.path.insert(0,'$AI_DIR'); import sys_message"
echo ""

echo "[5] 数据目录"
DATA_OK=0
for f in cpu.json io.json mem.json lock.json hot.json; do
	if [ -f "$REPORT_DIR/$f" ]; then
		((DATA_OK++))
	fi
done
echo "  [INFO] report/ 下有 $DATA_OK/5 个模块 JSON"
echo ""

echo "[6] 测试 API 连通性"
if [ "$KEY_OK" = true ] || [ -n "$DEEPSEEK_API_KEY" ]; then
	python3 -c "
import sys; sys.path.insert(0,'$AI_DIR')
from caller import _load_api_config
cfg = _load_api_config()
print('  [INFO] 当前 model:', cfg['model'], 'base_url:', cfg['base_url'])
" 2>/dev/null
else
	echo "  [SKIP] 无有效 API key"
fi

echo ""
echo "=== 检查完成: $PASS 通过, $FAIL 失败 ==="
[ "$FAIL" -eq 0 ] && echo "环境就绪" || echo "请修复以上失败项"
