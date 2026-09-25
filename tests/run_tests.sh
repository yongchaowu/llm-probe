#!/bin/sh
# llm_probe 分支测试：mock 服务 + py/sh 双实现，27 项断言
# 用法: ./run_tests.sh          （需 curl、openssl、python3；会短暂占用 18923 端口）
# 全部通过时输出 PASS=27 FAIL=0，退出码 0
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_DIR=$(dirname "$SCRIPT_DIR")
LOGDIR=$(mktemp -d)
trap 'rm -rf "$LOGDIR"' EXIT
set -u
cd "$REPO_DIR" || exit 1

BASE_URL=http://127.0.0.1:18923/v1
# 注意：这里刻意不 export 真实口令。
# 前 8 组用 --key 显式传密钥，第 9 组用临时配置 + 自己的口令，
# 因此测试不需要读取真实 .llm_probe.env 的解密口令。
PASS=0
FAIL=0

# 清掉上一轮可能残留的 mock，否则端口被占会导致 mode 切换失效
pkill -f '[m]ock_llm' 2>/dev/null
sleep 1

start_mock() {
    MOCK_MODE=$1 python3 "$SCRIPT_DIR"/mock_llm.py >"$LOGDIR"/mock.log 2>&1 &
    MOCK_PID=$!
    for _ in 1 2 3 4 5 6 7 8 9 10; do
        if curl -s -o /dev/null --max-time 1 "$BASE_URL/"; then break; fi
        sleep 0.3
    done
    if ! kill -0 "$MOCK_PID" 2>/dev/null; then
        echo "mock 起不来（端口被残留进程占用？）"; cat "$LOGDIR"/mock.log; exit 1
    fi
}
stop_mock() { kill "$MOCK_PID" 2>/dev/null; wait "$MOCK_PID" 2>/dev/null; }

check() {  # $1=描述 $2=期望退出码 $3=实际
    if [ "$2" -eq "$3" ]; then
        PASS=$((PASS + 1)); printf '  ✅ %-46s exit=%s\n' "$1" "$3"
    else
        FAIL=$((FAIL + 1)); printf '  ❌ %-46s 期望 exit=%s 实际=%s\n' "$1" "$2" "$3"
    fi
}

echo "== 1. 正常端点 (mock ok) =="
start_mock ok
python3 llm_probe.py probe --base-url "$BASE_URL" --model mock-a --key sk-good >"$LOGDIR"/t1.log 2>&1
check "py probe 正常端点" 0 $?
./llm_probe.sh probe --base-url "$BASE_URL" --model mock-a --key sk-good >"$LOGDIR"/t2.log 2>&1
check "sh probe 正常端点" 0 $?
grep -q "mock 回复" "$LOGDIR"/t1.log && echo "  ✅ py 抓到回复内容" || { echo "  ❌ py 没抓到回复"; FAIL=$((FAIL+1)); }
grep -q "mock 回复" "$LOGDIR"/t2.log && echo "  ✅ sh 抓到回复内容" || { echo "  ❌ sh 没抓到回复"; FAIL=$((FAIL+1)); }

python3 llm_probe.py probe --base-url "$BASE_URL" --model mock-a --key sk-bad >/dev/null 2>&1
check "py 错误密钥 → 3" 3 $?
./llm_probe.sh probe --base-url "$BASE_URL" --model mock-a --key sk-bad >/dev/null 2>&1
check "sh 错误密钥 → 3" 3 $?

python3 llm_probe.py probe --base-url "$BASE_URL" --model mock-a --key sk-good --json \
    >"$LOGDIR"/tj1.json 2>/dev/null
python3 -c "import json,sys; d=json.load(open('"$LOGDIR"/tj1.json')); sys.exit(d['exit_code'])"
check "py --json 合法且 exit_code=0" 0 $?
./llm_probe.sh probe --base-url "$BASE_URL" --model mock-a --key sk-good --json \
    >"$LOGDIR"/tj2.json 2>/dev/null
python3 -c "import json,sys; d=json.load(open('"$LOGDIR"/tj2.json')); sys.exit(d['exit_code'])"
check "sh --json 合法且 exit_code=0" 0 $?

python3 llm_probe.py probe --base-url "$BASE_URL" --model mock-a --key sk-good --sdk \
    >"$LOGDIR"/t3.log 2>&1
check "py --sdk (openai 0.28 老 API)" 0 $?
grep -q "openai 0.28" "$LOGDIR"/t3.log && echo "  ✅ SDK 兼容分支命中 0.28" || { echo "  ❌ 未走 0.28 分支"; FAIL=$((FAIL+1)); }
stop_mock

echo "== 2. 端点 401 (unauthorized) =="
start_mock unauthorized
python3 llm_probe.py probe --base-url "$BASE_URL" --model mock-a --key sk-good >/dev/null 2>&1
check "py 全站 401 → 3" 3 $?
./llm_probe.sh probe --base-url "$BASE_URL" --model mock-a --key sk-good >/dev/null 2>&1
check "sh 全站 401 → 3" 3 $?
python3 llm_probe.py probe --base-url "$BASE_URL" --model mock-a --key sk-good --all >"$LOGDIR"/t4.log 2>&1
check "py --all 强制跑 L3 仍 3" 3 $?
stop_mock

echo "== 3. 路径不对 (badpath 404) =="
start_mock badpath
python3 llm_probe.py probe --base-url "$BASE_URL" --model mock-a --key sk-good >"$LOGDIR"/t5.log 2>&1
check "py 路径 404 → 4" 4 $?
./llm_probe.sh probe --base-url "$BASE_URL" --model mock-a --key sk-good >"$LOGDIR"/t6.log 2>&1
check "sh 路径 404 → 4" 4 $?
grep -q "路径不对" "$LOGDIR"/t5.log && echo "  ✅ py 结论提示 base_url 缺 /v1" || { echo "  ❌ py 结论不含路径提示"; FAIL=$((FAIL+1)); }
stop_mock

echo "== 4. 模型名不对 (badmodel 400) =="
start_mock badmodel
python3 llm_probe.py probe --base-url "$BASE_URL" --model nope --key sk-good >"$LOGDIR"/t7.log 2>&1
check "py 模型 400 → 4" 4 $?
./llm_probe.sh probe --base-url "$BASE_URL" --model nope --key sk-good >"$LOGDIR"/t8.log 2>&1
check "sh 模型 400 → 4" 4 $?
grep -q "多半是模型名不对" "$LOGDIR"/t7.log && echo "  ✅ py 结论指向模型名" || { echo "  ❌ py 结论缺模型名提示"; FAIL=$((FAIL+1)); }
stop_mock

echo "== 5. 限流 (ratelimit 429) =="
start_mock ratelimit
python3 llm_probe.py probe --base-url "$BASE_URL" --model mock-a --key sk-good >/dev/null 2>&1
check "py 429 → 4" 4 $?
./llm_probe.sh probe --base-url "$BASE_URL" --model mock-a --key sk-good >/dev/null 2>&1
check "sh 429 → 4" 4 $?
stop_mock

echo "== 6. 不实现 /models (noreduce) =="
start_mock noreduce
python3 llm_probe.py probe --base-url "$BASE_URL" --model mock-a --key sk-good >"$LOGDIR"/t9.log 2>&1
check "py /models 404 但推理成功 → 0" 0 $?
./llm_probe.sh probe --base-url "$BASE_URL" --model mock-a --key sk-good >"$LOGDIR"/t10.log 2>&1
check "sh /models 404 但推理成功 → 0" 0 $?
grep -q "认证跳过" "$LOGDIR"/t9.log && echo "  ✅ py 标注认证跳过" || { echo "  ❌ py 未标注认证跳过"; FAIL=$((FAIL+1)); }
stop_mock

echo "== 7. 网络层失败 =="
python3 llm_probe.py probe --base-url http://127.0.0.1:18999/v1 --model mock-a --key sk-good >/dev/null 2>&1
check "py 端口未监听 → 2" 2 $?
./llm_probe.sh probe --base-url http://127.0.0.1:18999/v1 --model mock-a --key sk-good >/dev/null 2>&1
check "sh 端口未监听 → 2" 2 $?
python3 llm_probe.py probe --base-url http://no-such-host-xyz.invalid/v1 --model mock-a --key sk-good >"$LOGDIR"/t11.log 2>&1
check "py DNS 失败 → 2" 2 $?
./llm_probe.sh probe --base-url http://no-such-host-xyz.invalid/v1 --model mock-a --key sk-good >"$LOGDIR"/t12.log 2>&1
check "sh DNS 失败 → 2" 2 $?
grep -q "DNS 解析失败" "$LOGDIR"/t11.log && echo "  ✅ py 识别 DNS 错误" || { echo "  ❌ py 未识别 DNS"; FAIL=$((FAIL+1)); }
grep -q "DNS 解析失败" "$LOGDIR"/t12.log && echo "  ✅ sh 识别 DNS 错误" || { echo "  ❌ sh 未识别 DNS"; FAIL=$((FAIL+1)); }

echo "== 8. 用法错误 =="
python3 llm_probe.py probe --base-url ftp://x/v1 --model m >/dev/null 2>&1
check "py 非法 scheme → 1" 1 $?
./llm_probe.sh probe --base-url ftp://x/v1 --model m >/dev/null 2>&1
check "sh 非法 scheme → 1" 1 $?
python3 llm_probe.py --only net --base-url http://127.0.0.1:18999/v1 >/dev/null 2>&1
check "py --only net 端口不通 → 2" 2 $?

echo "== 9. 密文互通 =="
TMPDIR_T=$(mktemp -d)
cp .llm_probe.env "$TMPDIR_T/py.env"
# sh 端加密 → py 端解密
cat > "$TMPDIR_T/sh.env" <<EOF
LLM_BASE_URL=$BASE_URL
LLM_MODEL=mock-a
LLM_API_KEY_ENC=
EOF
./llm_probe.sh -c "$TMPDIR_T/sh.env" setkey --key 'sk-cross-test' --passphrase 'cross-2026' >"$LOGDIR"/t13.log 2>&1
grep -q '^LLM_API_KEY_ENC=enc:v1:' "$TMPDIR_T/sh.env" && echo "  ✅ sh setkey 写入密文" || { echo "  ❌ sh setkey 未写入"; FAIL=$((FAIL+1)); }
GOT=$(python3 llm_probe.py -c "$TMPDIR_T/sh.env" showkey --plain --passphrase 'cross-2026' 2>/dev/null)
[ "$GOT" = "sk-cross-test" ] && echo "  ✅ py 能解 sh 写的密文" || { echo "  ❌ py 解 sh 密文失败: $GOT"; FAIL=$((FAIL+1)); }
# py 端加密 → sh 端解密
python3 llm_probe.py -c "$TMPDIR_T/py2.env" init >/dev/null 2>&1
python3 llm_probe.py -c "$TMPDIR_T/py2.env" setkey --key 'sk-cross-test2' --passphrase 'cross-2026' >/dev/null 2>&1
GOT=$(./llm_probe.sh -c "$TMPDIR_T/py2.env" showkey --plain --passphrase 'cross-2026' 2>/dev/null)
[ "$GOT" = "sk-cross-test2" ] && echo "  ✅ sh 能解 py 写的密文" || { echo "  ❌ sh 解 py 密文失败: $GOT"; FAIL=$((FAIL+1)); }
# 错误口令必须失败
python3 llm_probe.py -c "$TMPDIR_T/sh.env" showkey --passphrase 'wrong' >/dev/null 2>&1
check "py 错误口令 → 非0" 1 $?
./llm_probe.sh -c "$TMPDIR_T/sh.env" showkey --passphrase 'wrong' >/dev/null 2>&1
check "sh 错误口令 → 非0" 1 $?
rm -rf "$TMPDIR_T"

echo "== 10. 配置文件不被当代码执行 =="
CFG=$(mktemp "$LOGDIR"/evilXXXX.env)
printf 'LLM_BASE_URL=http://127.0.0.1:18999/v1\nLLM_MODEL=m\n# $(touch /tmp/opencode/pwned)\n' > "$CFG"
rm -f /tmp/opencode/pwned
./llm_probe.sh -c "$CFG" probe >/dev/null 2>&1
[ ! -f /tmp/opencode/pwned ] && echo "  ✅ sh 不执行配置文件内容" || { echo "  ❌ 配置被当命令执行了!"; FAIL=$((FAIL+1)); }
python3 llm_probe.py -c "$CFG" probe >/dev/null 2>&1
[ ! -f /tmp/opencode/pwned ] && echo "  ✅ py 不执行配置文件内容" || { echo "  ❌ 配置被当命令执行了!"; FAIL=$((FAIL+1)); }
rm -f "$CFG"

echo
echo "=================================="
echo "PASS=$PASS  FAIL=$FAIL"
echo "=================================="
[ "$FAIL" -eq 0 ]
