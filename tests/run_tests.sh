#!/bin/sh
# llm_probe 分支测试：mock 服务 + py/sh 双实现，16 组场景、70 项断言
# 用法: ./run_tests.sh          （需 curl、openssl、python3；会短暂占用 18923 端口）
# 全部通过时输出 PASS=70 FAIL=0，退出码 0
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

echo "== 11. 口令不泄漏给子进程 =="
# 用 shim 包一层 curl/openssl，记录它们各自环境里出现 LLM_PASSPHRASE 的次数
SHIM="$LOGDIR/shim"
mkdir -p "$SHIM"
REAL_CURL=$(command -v curl)
REAL_OPENSSL=$(command -v openssl)
cat > "$SHIM/curl" <<EOF
#!/bin/sh
env | grep -c '^LLM_PASSPHRASE=' >> "$LOGDIR/curl_pp"
exec $REAL_CURL "\$@"
EOF
cat > "$SHIM/openssl" <<EOF
#!/bin/sh
env | grep -c '^LLM_PASSPHRASE=' >> "$LOGDIR/openssl_pp"
exec $REAL_OPENSSL "\$@"
EOF
chmod +x "$SHIM/curl" "$SHIM/openssl"
LEAKDIR=$(mktemp -d)
python3 llm_probe.py -c "$LEAKDIR/leak.env" init >/dev/null 2>&1
python3 llm_probe.py -c "$LEAKDIR/leak.env" setkey --key 'sk-leak-test' --passphrase 'leak-2026' >/dev/null 2>&1
rm -f "$LOGDIR/curl_pp" "$LOGDIR/openssl_pp"
PATH="$SHIM:$PATH" LLM_PASSPHRASE='leak-2026' \
    ./llm_probe.sh -c "$LEAKDIR/leak.env" probe --only auth >/dev/null 2>&1
grep -q '^[1-9]' "$LOGDIR/curl_pp" 2>/dev/null && RCBAD=1 || RCBAD=0
check "sh 口令不出现在 curl 子进程环境里" 0 $RCBAD
grep -q '^[1-9]' "$LOGDIR/openssl_pp" 2>/dev/null && RCGOOD=0 || RCGOOD=1
check "sh 口令确实喂给了 openssl（解密能用）" 0 $RCGOOD
LLM_PASSPHRASE='unit-pw' python3 - >"$LOGDIR"/env_scrub.log 2>&1 <<'PY'
import os, subprocess, sys
sys.path.insert(0, ".")
import llm_probe

class A:
    passphrase = None

pw = llm_probe.read_passphrase(A(), {})
n = subprocess.run(["sh", "-c", "env | grep -c '^LLM_PASSPHRASE='"],
                   capture_output=True, text=True, check=False).stdout.strip()
sys.exit(0 if (pw == "unit-pw" and "LLM_PASSPHRASE" not in os.environ and n == "0") else 1)
PY
check "py 读到口令即摘除、子进程看不到" 0 $?

echo "== 12. setkey 走 stdin（非交互免 argv）=="
printf 'sk-stdin-11\n' | ./llm_probe.sh -c "$LEAKDIR/s11.env" setkey --passphrase 'pw-stdin' >/dev/null 2>&1
GOT=$(./llm_probe.sh -c "$LEAKDIR/s11.env" showkey --plain --passphrase 'pw-stdin' 2>/dev/null)
[ "$GOT" = "sk-stdin-11" ] && RC=0 || RC=1
check "sh setkey 从 stdin 读密钥并可解开" 0 $RC
printf 'sk-stdin-12\n' | python3 llm_probe.py -c "$LEAKDIR/s12.env" setkey --passphrase 'pw-stdin' >/dev/null 2>&1
GOT=$(python3 llm_probe.py -c "$LEAKDIR/s12.env" showkey --plain --passphrase 'pw-stdin' 2>/dev/null)
[ "$GOT" = "sk-stdin-12" ] && RC=0 || RC=1
check "py setkey 从 stdin 读密钥并可解开" 0 $RC
./llm_probe.sh -c "$LEAKDIR/s13.env" setkey --passphrase 'pw' </dev/null >/dev/null 2>&1
check "sh 非交互且无输入 → 1" 1 $?
python3 llm_probe.py -c "$LEAKDIR/s14.env" setkey --passphrase 'pw' </dev/null >/dev/null 2>&1
check "py 非交互且无输入 → 1" 1 $?

echo "== 13. 老 openssl（无 -pbkdf2）给出可读报错 =="
OLDSSL="$LOGDIR/oldssl"
mkdir -p "$OLDSSL"
cat > "$OLDSSL/openssl" <<EOF
#!/bin/sh
for a in "\$@"; do
  if [ "\$a" = "-pbkdf2" ]; then
    echo "enc: Unknown option -pbkdf2" >&2
    exit 1
  fi
done
exec $REAL_OPENSSL "\$@"
EOF
chmod +x "$OLDSSL/openssl"
PATH="$OLDSSL:$PATH" ./llm_probe.sh -c "$LEAKDIR/leak.env" showkey --plain \
    --passphrase 'leak-2026' >"$LOGDIR"/t20.log 2>&1
check "sh 老 openssl → 1" 1 $?
grep -q "不支持 -pbkdf2" "$LOGDIR"/t20.log && RC=0 || RC=1
check "sh 报错说清了原因与出路" 0 $RC
PATH="$OLDSSL:$PATH" python3 - >"$LOGDIR"/t21.log 2>&1 <<'PY'
import sys
sys.path.insert(0, ".")
import llm_probe
llm_probe._OPENSSL_PBKDF2_OK = None      # 强制重新探测
sys.exit(0 if not llm_probe._openssl_pbkdf2_ok() else 1)
PY
check "py 识别老 openssl 不支持 -pbkdf2" 0 $?
rm -rf "$LEAKDIR"

echo "== 14. 单元测试 =="
python3 "$SCRIPT_DIR"/test_units.py >"$LOGDIR"/units.log 2>&1
RC=$?
check "tests/test_units.py 全部通过" 0 $RC
[ "$RC" -eq 0 ] || tail -6 "$LOGDIR"/units.log

echo "== 15. py / sh 跨实现结论一致（JSON 逐字段）=="
for mode in ok unauthorized badpath badmodel ratelimit noreduce; do
    start_mock "$mode"
    python3 llm_probe.py probe --base-url "$BASE_URL" --model mock-a --key sk-good --json \
        >"$LOGDIR"/x.json 2>/dev/null
    ARC=$?
    ./llm_probe.sh probe --base-url "$BASE_URL" --model mock-a --key sk-good --json \
        >"$LOGDIR"/y.json 2>/dev/null
    BRC=$?
    stop_mock
    python3 - "$LOGDIR"/x.json "$LOGDIR"/y.json "$ARC" "$BRC" >"$LOGDIR"/cmp.log 2>&1 <<'PY'
import json, re, sys
a = json.load(open(sys.argv[1]))
b = json.load(open(sys.argv[2]))
ar, br = int(sys.argv[3]), int(sys.argv[4])

def norm(d):
    return [(s["name"], bool(s.get("ok")), bool(s.get("skipped", False)))
            for s in d["steps"]]

def detail(d, name):
    for s in d["steps"]:
        if s["name"] == name:
            return s.get("detail", "")
    return "(缺该步)"

def norm_text(x):      # 耗时是环境相关的，归一化后再比
    return re.sub(r"\(\d+(\.\d+)?ms\)", "(T)", x)

problems = []
if not (a["exit_code"] == b["exit_code"] == ar == br):
    problems.append(f"exit_code {a['exit_code']}/{b['exit_code']}/{ar}/{br}")
if norm(a) != norm(b):
    problems.append(f"steps {norm(a)} vs {norm(b)}")
if a["verdict"] != b["verdict"]:
    problems.append(f"verdict {a['verdict']!r} vs {b['verdict']!r}")
for key in ("version", "base_url", "model", "key_masked", "key_source",
            "config", "verdict", "exit_code"):
    if key not in a or key not in b:
        problems.append(f"JSON 缺字段 {key}")
# L2 / L3 的 detail 文案必须逐字一致（L1 是有意差异：py 报证书信息，
# sh 报 remote IP 与握手耗时，见 README「两个实现的有意差异」）
for step in ("L2 认证", "L3 推理"):
    if norm_text(detail(a, step)) != norm_text(detail(b, step)):
        problems.append(f"{step} detail {detail(a, step)!r} vs {detail(b, step)!r}")
if problems:
    print("; ".join(problems))
    sys.exit(1)
sys.exit(0)
PY
    check "$mode: py/sh 退出码+步骤+结论+detail+schema 一致" 0 $?
done

echo "== 16. 自查发现的缺陷回归 =="
REG=$(mktemp -d)
# 16.1 参数错误退出码：argparse 默认 2 会和网络不通撞码
python3 llm_probe.py probe --timeout abc >/dev/null 2>&1
check "py 参数非法 → 1（不是 2）" 1 $?
python3 llm_probe.py probe --no-such-flag >/dev/null 2>&1
check "py 未知参数 → 1（不是 2）" 1 $?
# 16.2 显式 0 不能绕过"必须大于 0"（`args.x or ...` 的假值陷阱）
python3 llm_probe.py -c "$LEAKDIR/zero.env" probe --max-tokens 0 >/dev/null 2>&1
check "py --max-tokens 0 → 1" 1 $?
./llm_probe.sh -c "$LEAKDIR/zero.env" probe --timeout 0 >/dev/null 2>&1
check "sh --timeout 0 → 1" 1 $?
# 16.3 畸形配置：两端都干净退出 1，且不能出现 traceback
printf '=空键\n' > "$REG/bad.env"
python3 llm_probe.py -c "$REG/bad.env" probe >"$LOGDIR"/t30.log 2>&1
RC=$?
check "py 畸形配置 → 1" 1 $RC
grep -q "Traceback" "$LOGDIR"/t30.log && RC=1 || RC=0
check "py 畸形配置无 traceback" 0 $RC
./llm_probe.sh -c "$REG/bad.env" probe >"$LOGDIR"/t31.log 2>&1
RC=$?
check "sh 畸形配置 → 1（以前会照跑）" 1 $RC
grep -q "第 1" "$LOGDIR"/t31.log && RC=0 || RC=1
check "sh 畸形配置指出行号" 0 $RC
# 16.4 stdin 喂密钥、末尾无换行（README 推荐的写法，sh 以前读不到）
printf 'sk-no-newline-sh' | ./llm_probe.sh -c "$REG/nl.env" setkey --passphrase 'pw' >/dev/null 2>&1
GOT=$(./llm_probe.sh -c "$REG/nl.env" showkey --plain --passphrase 'pw' 2>/dev/null)
[ "$GOT" = "sk-no-newline-sh" ] && RC=0 || RC=1
check "sh stdin 无尾换行也能 setkey" 0 $RC
# 16.5 配置里的引号两端都要剥（sh 以前没剥，带引号的密文解不开）
printf 'sk-quoted\n' | python3 llm_probe.py -c "$REG/q.env" setkey --passphrase 'pw' >/dev/null 2>&1
python3 - "$REG/q.env" <<'PY'
import sys
p = sys.argv[1]
lines = [l for l in open(p, encoding="utf-8").read().splitlines()]
out = []
for l in lines:
    if l.startswith("LLM_API_KEY_ENC=enc:v1:"):
        l = 'LLM_API_KEY_ENC="' + l.split("=", 1)[1] + '"'
    out.append(l)
open(p, "w", encoding="utf-8").write("\n".join(out) + "\n")
PY
GOT=$(./llm_probe.sh -c "$REG/q.env" showkey --plain --passphrase 'pw' 2>/dev/null)
[ "$GOT" = "sk-quoted" ] && RC=0 || RC=1
check "sh 能解开带引号的密文配置" 0 $RC
# 16.5b 双引号剥离（sh 的 case 模式写坏过，所有 "值" 都会带着引号跑）
printf 'LLM_BASE_URL="http://127.0.0.1:18923/v1"\nLLM_PROMPT="带 空格 的提示"\n' > "$REG/quote.env"
GOT=$(./llm_probe.sh -c "$REG/quote.env" env 2>/dev/null | sed -n 's/^LLM_BASE_URL *= //p')
[ "$GOT" = "http://127.0.0.1:18923/v1" ] && RC=0 || RC=1
check "sh 剥双引号（base_url 以前带引号）" 0 $RC
GOT=$(python3 llm_probe.py -c "$REG/quote.env" env 2>/dev/null | sed -n 's/^LLM_BASE_URL *= //p')
[ "$GOT" = "http://127.0.0.1:18923/v1" ] && RC=0 || RC=1
check "py 剥双引号" 0 $RC
GOT=$(./llm_probe.sh -c "$REG/quote.env" env 2>/dev/null | sed -n 's/^LLM_PROMPT *= //p')
[ "$GOT" = "带 空格 的提示" ] && RC=0 || RC=1
check "sh 剥双引号且保留内部空格" 0 $RC
# 16.6 口令文件路径里的 ~ 要展开（py 用 expanduser，sh 以前找不到）
printf 'pw-tilde' > "$HOME/.llm_probe_test_pw"
printf 'LLM_PASSPHRASE_FILE=~/.llm_probe_test_pw\n' > "$REG/tilde.env"
python3 llm_probe.py -c "$REG/tilde.env" setkey --key 'sk-tilde-py' >/dev/null 2>&1
GOT=$(./llm_probe.sh -c "$REG/tilde.env" showkey --plain 2>/dev/null)
rm -f "$HOME/.llm_probe_test_pw"
[ "$GOT" = "sk-tilde-py" ] && RC=0 || RC=1
check "sh 口令文件 ~ 展开（与 py 一致）" 0 $RC
# 16.7 用 --key 时，环境里那份 LLM_API_KEY 也要摘掉
printf 'LLM_BASE_URL=http://127.0.0.1:18923/v1\nLLM_MODEL=mock-a\n' > "$REG/probe.env"
KEYSHIM="$LOGDIR/keyshim"
mkdir -p "$KEYSHIM"
cat > "$KEYSHIM/curl" <<SHIMEOF
#!/bin/sh
env | grep -c '^LLM_API_KEY=' >> "$LOGDIR/curl_key"
exec $REAL_CURL "$@"
SHIMEOF
chmod +x "$KEYSHIM/curl"
rm -f "$LOGDIR/curl_key"
LLM_API_KEY='sk-env-should-be-scrubbed' PATH="$KEYSHIM:$PATH" \
    ./llm_probe.sh -c "$REG/probe.env" probe --only net --key 'sk-cli-arg' >/dev/null 2>&1
# 先确认 curl 真的跑起来了，否则"没泄漏"是假通过
[ -f "$LOGDIR/curl_key" ] && RC=0 || RC=1
check "sh curl 子进程确实被执行（防止假通过）" 0 $RC
grep -q '^[1-9]' "$LOGDIR/curl_key" 2>/dev/null && RC=1 || RC=0
check "sh --key 时环境 key 不传子进程" 0 $RC
LLM_API_KEY='sk-env-should-be-scrubbed' python3 - >/dev/null 2>&1 <<'PY'
import os, sys
sys.path.insert(0, ".")
import llm_probe

class A:
    key = "sk-cli-arg"
    passphrase = None

llm_probe.resolve_key(A(), {})
sys.exit(0 if "LLM_API_KEY" not in os.environ else 1)
PY
check "py --key 时环境 key 也摘掉" 0 $?
# --only net 这条路径整段跳过密钥解析，最容易漏掉摘除动作（这里就是回归点）
rm -f "$LOGDIR/curl_key"
LLM_API_KEY='sk-env-should-be-scrubbed' PATH="$KEYSHIM:$PATH" \
    ./llm_probe.sh -c "$REG/probe.env" probe --only net >/dev/null 2>&1
[ -f "$LOGDIR/curl_key" ] && grep -q '^0$' "$LOGDIR/curl_key" && RC=0 || RC=1
check "sh --only net 也不把环境 key 传给 curl" 0 $RC
LLM_API_KEY='sk-env-should-be-scrubbed' python3 - >/dev/null 2>&1 <<PY
import os, sys
sys.path.insert(0, ".")
import llm_probe

args = llm_probe.build_parser().parse_args(
    ["probe", "-c", "$REG/probe.env", "--only", "net",
     "--base-url", "http://127.0.0.1:9/v1", "--model", "m"])
llm_probe.cmd_probe(args)      # 连 127.0.0.1:9 会被立刻拒绝，不产生真实外部流量
sys.exit(0 if "LLM_API_KEY" not in os.environ else 1)
PY
check "py --only net 也摘掉环境 key" 0 $?
# 16.8 env 子命令传 --key 也要警告（sh 以前不警告）
./llm_probe.sh -c "$REG/probe.env" env --key 'sk-arg' 2>&1 >/dev/null | grep -q -- "--key" && RC=0 || RC=1
check "sh env --key 打警告" 0 $RC
python3 llm_probe.py -c "$REG/probe.env" env --key 'sk-arg' 2>&1 >/dev/null | grep -q -- "--key" && RC=0 || RC=1
check "py env --key 打警告" 0 $RC
# 16.9 优先级：命令行 > 环境变量 > 配置，要真的发到线上（mock 校验 max_tokens）
printf 'LLM_MAX_TOKENS=8\n' > "$REG/pri.env"
start_mock checkmaxtokens
LLM_MAX_TOKENS=7 ./llm_probe.sh -c "$REG/pri.env" probe --base-url "$BASE_URL" --model mock-a --key sk-good >/dev/null 2>&1
check "sh 环境变量 max_tokens 覆盖配置（到了线上）" 0 $?
./llm_probe.sh -c "$REG/pri.env" probe --base-url "$BASE_URL" --model mock-a --key sk-good --max-tokens 7 >/dev/null 2>&1
check "sh 命令行 max_tokens 覆盖配置" 0 $?
./llm_probe.sh -c "$REG/pri.env" probe --base-url "$BASE_URL" --model mock-a --key sk-good >/dev/null 2>&1
check "sh 配置里的 max_tokens=8 确实发出去了 → 4" 4 $?
LLM_MAX_TOKENS=7 python3 llm_probe.py -c "$REG/pri.env" probe --base-url "$BASE_URL" --model mock-a --key sk-good >/dev/null 2>&1
check "py 环境变量 max_tokens 覆盖配置" 0 $?
python3 llm_probe.py -c "$REG/pri.env" probe --base-url "$BASE_URL" --model mock-a --key sk-good --max-tokens 7 >/dev/null 2>&1
check "py 命令行 max_tokens 覆盖配置" 0 $?
stop_mock
rm -rf "$REG"

echo
echo "=================================="
echo "PASS=$PASS  FAIL=$FAIL"
echo "=================================="
[ "$FAIL" -eq 0 ]
