#!/bin/sh
# llm_probe.sh —— OpenAI 兼容 LLM 端点连通性探测（curl + openssl 版）
#
# 与 llm_probe.py 是同一套工具的两个实现：
#   * 读同一份 .llm_probe.env 配置
#   * 认同一种密文格式 enc:v1:（openssl AES-256-CBC + PBKDF2-SHA256/300000）
#   * 返回同样的退出码：0 通过 / 1 用法 / 2 网络 / 3 认证 / 4 推理
#
# 严格 POSIX，dash / bash / macOS 默认 shell 都能跑；不依赖 Python。
#
# 用法:
#   ./llm_probe.sh probe                 分层探测（默认动作）
#   ./llm_probe.sh init                  生成配置文件
#   ./llm_probe.sh setkey                加密写入 API Key
#   ./llm_probe.sh showkey               解密显示（默认打码）
#   ./llm_probe.sh env                   打印生效配置
#
# 常用参数（probe）:
#   -c FILE      指定配置文件
#   --base-url / --model / --prompt / --timeout / --max-tokens
#   --only net|auth|infer    只跑某一层
#   --all                    认证失败也继续测推理
#   --matrix                 五项 OpenAI 兼容能力矩阵
#   --allow-unsupported      chat 已通过时，矩阵中仅 404/405 未实现能力仍返回 0
#   --direct                 不走系统代理
#   --json                   JSON 输出

# 刻意只用 `set -u`，不用 `set -e`：
# 这个脚本的核心是"抓住 curl/openssl 的非零退出码来分类故障"。`set -e` 会在
# 第一个失败的 `err=$(curl ...)` 处直接中止，导致：
#   * 端口不通时一行报告都不打印（实测 0 行输出），只留下 curl 的原始退出码 7
#   * 期望的"退出码 2 + 12 行分层报告"完全丢失
# 每个关键命令的退出状态都在下面显式判断（curl → classify_curl_error，
# openssl → decrypt_key 的 if ! ... ），漏掉的靠 tests/run_tests.sh 兜底。
set -u

VERSION="1.1"
PROG="llm_probe.sh"
ENC_PREFIX="enc:v1:"
PBKDF2_ITER=300000
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
DEFAULT_CONFIG="$SCRIPT_DIR/.llm_probe.env"

CONFIG="$DEFAULT_CONFIG"
CMD=""
BASE_URL=""
MODEL=""
PROMPT=""
TIMEOUT=""
MAX_TOKENS=""
KEY=""
PASSPHRASE_ARG=""
ONLY=""
ALL=0
JSON=0
DIRECT=0
PLAIN=0
FORCE=0

BODY_FILE=""
ERR_FILE=""
HEAD_FILE=""
HEADER_FILE=""
TMP_DIR=""
PASSPHRASE=""
MATRIX=0
ALLOW_UNSUPPORTED=0

# load_config 可能因配置文件缺失而提前返回，这些全局必须先初始化（set -u）
API_KEY_ENC=""
API_KEY_PLAIN=""
PASSPHRASE_FILE=""
KEY=""
KEY_SOURCE=""
STEP2_RAN=0
LAST_CURL_MSG=""

# ---------------------------------------------------------------------------
# 输出工具
# ---------------------------------------------------------------------------
die() { printf '%s\n' "$*" >&2; exit 1; }

# 命令行参数里的密钥会同时留在 shell 历史和 ps 进程列表里
warn_secret_arg() {  # $1 = 参数名
    printf '⚠ 警告: %s 会留在 shell 历史和进程列表 (ps) 里，仅建议临时测试用；日常请用交互输入、stdin 管道或环境变量。\n' "$1" >&2
}

cleanup() {
    [ -n "${TMP_DIR:-}" ] && rm -rf "$TMP_DIR"
    [ -n "$BODY_FILE" ] && rm -f "$BODY_FILE"
    [ -n "$ERR_FILE" ] && rm -f "$ERR_FILE"
    [ -n "$HEAD_FILE" ] && rm -f "$HEAD_FILE"
    [ -n "$HEADER_FILE" ] && rm -f "$HEADER_FILE"
}
# 收到信号要"清干净 + 立刻退出"：只 cleanup 不 exit 的话，脚本会从被打断的
# 那一行继续往下跑，Ctrl-C 之后还可能打出一份半截报告。
trap cleanup EXIT
trap 'cleanup; trap - INT; exit 130' INT
trap 'cleanup; trap - TERM; exit 143' TERM
trap 'cleanup; trap - HUP; exit 129' HUP
trap 'cleanup; trap - QUIT; exit 131' QUIT

# 临时响应体集中放在一个私有目录里（umask 077 → 0700），退出即删。
# 注意：kill -9 / SIGKILL 不触发 trap，目录会残留；下次运行是新建目录，不会
# 复用旧的。彻底清理: rm -rf "${TMPDIR:-/tmp}"/llm_probe.*
init_tmpdir() {
    umask 077
    TMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/llm_probe.XXXXXX") || die "mktemp -d 失败：无法创建临时目录"
    BODY_FILE="$TMP_DIR/response.json"
    ERR_FILE="$TMP_DIR/curl.err"
    HEAD_FILE="$TMP_DIR/response.headers"
    HEADER_FILE="$TMP_DIR/request.headers"
    : > "$BODY_FILE"
    : > "$ERR_FILE"
    : > "$HEAD_FILE"
    : > "$HEADER_FILE"
}

usage() {
    cat <<EOF
$PROG $VERSION —— OpenAI 兼容 LLM 端点连通性探测（curl + openssl，零 Python 依赖）

用法:
  $PROG [probe] [选项]      分层探测（默认动作）
  $PROG init [--force]      生成配置文件
  $PROG setkey [--key K]    加密写入 API Key
  $PROG showkey [--plain]   解密显示 API Key
  $PROG env                 打印生效配置

探测选项:
  -c FILE           配置文件（默认: $DEFAULT_CONFIG）
  --base-url URL    端点地址，如 https://api.openai.com/v1
  --model NAME      模型名
  --prompt TEXT     测试提示词（默认取配置 LLM_PROMPT）
  --timeout SEC     超时秒数（默认取配置 LLM_TIMEOUT）
  --max-tokens N    最大生成 token（默认 64）
  --key KEY         临时密钥（会进 shell 历史和 ps，仅临时测试用）
  --passphrase PWD  解密口令（同上；推荐口令文件或交互输入）
  --only LEVEL      只跑某一层: net=L1 / auth=L1+L2 / infer=L1+L3
  --all             认证失败也继续测推理
  --matrix          五项 OpenAI 兼容能力矩阵
  --allow-unsupported  chat 已通过时，矩阵中仅 404/405 未实现能力仍返回 0
  --direct          不走系统代理（绕过 http_proxy/https_proxy）
  --json            JSON 输出

密钥选项:
  setkey            交互输入密钥（推荐）
  printf '%s' "\$K" | setkey     非交互：从 stdin 读，不进 argv / 历史
  setkey --key K    直接给密钥（会留在 shell 历史和 ps 进程列表里）
  setkey/showkey --passphrase P  口令直接给（同上；推荐口令文件或交互）

退出码:
  0 全部通过   1 用法/配置错误   2 网络不通   3 认证失败   4 推理/兼容失败

示例:
  $PROG init
  $PROG setkey
  $PROG probe
  $PROG probe --only net --json
  $PROG probe --base-url https://api.openai.com/v1 --model gpt-4o-mini
EOF
    exit "${1:-0}"
}

# ---------------------------------------------------------------------------
# 配置文件读取（绝不 source，避免把配置当 shell 代码执行）
# ---------------------------------------------------------------------------
cfg_get() {  # $1 = 变量名；取配置文件里最后一次出现的值
    [ -f "$CONFIG" ] || return 0
    sed -n "s/^[[:space:]]*$1[[:space:]]*=[[:space:]]*//p" "$CONFIG" | tail -n 1
}

strip_quotes() {
    # 模式必须写 \"*（转义的双引号 + 任意），不能写 '"'"'"*：
    # 后者是转义搞坏的产物，实际匹配的是"单引号+双引号"，于是所有双引号
    # 包裹的值（LLM_BASE_URL="..."）都原样带着引号往下走。
    case $1 in
        \"*)  printf '%s' "$1" | sed 's/^"//; s/"$//' ;;
        "'"*) printf '%s' "$1" | sed "s/^'//; s/'\$//" ;;
        *)    printf '%s' "$1" ;;
    esac
}

expand_tilde() {  # $1 = 路径；补上 shell 不会做的一步（变量里的 ~ 不展开）
    case $1 in
        '~')      printf '%s' "$HOME" ;;
        '~/'*)    _rest=${1#?}                 # 去掉开头的 ~
                  printf '%s' "$HOME/${_rest#/}" ;;
        *)        printf '%s' "$1" ;;
    esac
}

# 配置是数据：格式不对直接指出行号退出（严格度与 llm_probe.py 对齐）
validate_config() {
    bad=$(awk '
        { line = $0
          sub(/^[ \t]+/, "", line)
          sub(/[ \t]+$/, "", line)
          if (line == "" || line ~ /^#/) next
          if (index(line, "=") == 0) { printf("%d: 不是 KEY=VALUE", NR); exit }
          if (substr(line, 1, 1) == "=") { printf("%d: KEY 为空", NR); exit }
        }' "$CONFIG") || true
    [ -z "$bad" ] || die "配置文件格式错误（第 $bad 行）: $CONFIG"
}

load_config() {
    # 注意：配置文件不存在时只是"没东西可读"，默认值与校验仍要往下走
    # （setkey 首次创建配置的场景正好会走到这里）。
    if [ -f "$CONFIG" ]; then
        validate_config
        # 优先级：命令行 > 环境变量 > 配置文件。
        # 命令行值在 main() 里于本函数**之后**套用，这里对已有的非空值保持不动，
        # 避免"谁最后赋值谁赢"这种隐式顺序依赖。
        if [ -z "${LLM_BASE_URL:-}" ]; then
            BASE_URL=$(strip_quotes "$(cfg_get LLM_BASE_URL)")
        else
            BASE_URL=$LLM_BASE_URL
        fi
        if [ -z "${LLM_MODEL:-}" ]; then
            MODEL=$(strip_quotes "$(cfg_get LLM_MODEL)")
        else
            MODEL=$LLM_MODEL
        fi
        [ -n "$TIMEOUT" ] || TIMEOUT="${LLM_TIMEOUT:-$(strip_quotes "$(cfg_get LLM_TIMEOUT)")}"
        [ -n "$PROMPT" ] || PROMPT="${LLM_PROMPT:-$(strip_quotes "$(cfg_get LLM_PROMPT)")}"
        [ -n "$MAX_TOKENS" ] || MAX_TOKENS="${LLM_MAX_TOKENS:-$(strip_quotes "$(cfg_get LLM_MAX_TOKENS)")}"
        PASSPHRASE_FILE="${LLM_PASSPHRASE_FILE:-$(strip_quotes "$(cfg_get LLM_PASSPHRASE_FILE)")}"
        [ -n "$PASSPHRASE_FILE" ] && PASSPHRASE_FILE=$(expand_tilde "$PASSPHRASE_FILE")
        API_KEY_ENC="${LLM_API_KEY_ENC:-$(strip_quotes "$(cfg_get LLM_API_KEY_ENC)")}"
        API_KEY_PLAIN="${LLM_API_KEY:-$(strip_quotes "$(cfg_get LLM_API_KEY)")}"
    fi

    [ -n "$TIMEOUT" ] || TIMEOUT=30
    [ -n "$PROMPT" ] || PROMPT="你好"
    [ -n "$MAX_TOKENS" ] || MAX_TOKENS=64
    validate_options
}

# 数值校验：curl 拿到 "--max-time abc" 只会含糊报错，这里给明确原因。
# 注意不能只写 awk '$1 > 0'：非数字字段（如 abc）与数字比较会走**字符串**
# 比较，"abc" > "0" 为真，会漏放；所以先 case 卡字符类，再做数值比较。
# 这个函数必须在"命令行参数已套用"之后调用（main 里会再调一次），否则
# --timeout abc / --max-tokens 0 这类 CLI 值会绕过检查。
validate_options() {
    case $TIMEOUT in
        ''|*[!0-9.]*|*.*.*) die "配置错误：LLM_TIMEOUT / --timeout 必须是数字，当前 '$TIMEOUT'" ;;
    esac
    printf '%s' "$TIMEOUT" | awk '{ exit !(($1 + 0) > 0) }' \
        || die "配置错误：LLM_TIMEOUT / --timeout 必须大于 0，当前 '$TIMEOUT'"
    case $MAX_TOKENS in
        ''|*[!0-9]*) die "配置错误：LLM_MAX_TOKENS / --max-tokens 必须是正整数，当前 '$MAX_TOKENS'" ;;
    esac
    printf '%s' "$MAX_TOKENS" | awk '{ exit !(($1 + 0) > 0) }' \
        || die "配置错误：LLM_MAX_TOKENS / --max-tokens 必须大于 0，当前 '$MAX_TOKENS'"
}

write_template() { # $1 = 目标文件
    cat > "$1" <<'EOF'
# llm_probe 配置文件（dotenv 风格）
# 注意：这是数据文件，不是 shell 脚本，llm_probe.sh 不会 source 它，
# 任何一行都不会被当作命令执行。
#
# 生成本文件:  ./llm_probe.sh init
# 写入密钥:    ./llm_probe.sh setkey
# 开始探测:    ./llm_probe.sh probe
#
# 也可以用 python3 llm_probe.py 操作同一份配置，两端密文互通。

# OpenAI 兼容端点，通常以 /v1 结尾。默认填官方地址；换服务商就改成它给的
# base_url。（README 里的 https://aiapiv2.pekpik.com/v1 是第三方中转示例，
# 别默认把密钥发给不认识的服务。）
LLM_BASE_URL=https://api.openai.com/v1

# 模型名按服务商自己的命名填
LLM_MODEL=gpt-4o-mini

# 加密后的密钥（enc:v1:... ），由 setkey 写入，不要手填
LLM_API_KEY_ENC=

# 明文密钥：仅用于临时调试。存在时优先级低于 LLM_API_KEY_ENC。
LLM_API_KEY=

# 解密口令文件（口令本身不写进本文件；也可以用环境变量 LLM_PASSPHRASE）
LLM_PASSPHRASE_FILE=

# 探测参数
LLM_TIMEOUT=30
LLM_PROMPT=你好
LLM_MAX_TOKENS=64
EOF
    chmod 600 "$1"
}

set_config_value() { # $1=KEY $2=VALUE  —— 原地替换或追加，保留注释
    key=$1
    value=$2
    if [ ! -f "$CONFIG" ]; then
        write_template "$CONFIG"
    fi
    if grep -q "^[[:space:]]*$key=" "$CONFIG"; then
        tmp=$(mktemp) || die "mktemp 失败：无法创建临时文件"
        # 用 awk 替换，避免 value 里的 & / 反斜杠被 sed 解释
        awk -v k="$key" -v v="$value" '
            index($0, k "=") == 1 || $0 ~ ("^[[:space:]]*" k "=") {
                print k "=" v; next
            }
            { print }
        ' "$CONFIG" > "$tmp" && mv "$tmp" "$CONFIG"
        chmod 600 "$CONFIG"
    else
        printf '%s=%s\n' "$key" "$value" >> "$CONFIG"
    fi
}

# ---------------------------------------------------------------------------
# 密钥加密 / 解密（openssl AES-256-CBC + PBKDF2-SHA256，与 Python 端互通）
# ---------------------------------------------------------------------------
require_openssl() {  # -pbkdf2 需要 OpenSSL >= 1.1.1（LibreSSL 不支持）
    [ "${OPENSSL_PBKDF2_OK:-}" = "1" ] && return 0
    command -v openssl >/dev/null 2>&1 \
        || die "找不到 openssl：加解密需要它（请安装 OpenSSL >= 1.1.1）"
    probe_file=$(mktemp "${TMPDIR:-/tmp}/llm_probe_pbkdf2.XXXXXX") || die "mktemp 失败"
    printf 'x' > "$probe_file"
    if openssl enc -aes-256-cbc -pbkdf2 -iter 1000 -md sha256 \
        -pass pass:probe -in "$probe_file" -out /dev/null 2>/dev/null; then
        rm -f "$probe_file"
        OPENSSL_PBKDF2_OK=1
    else
        rm -f "$probe_file"
        die "当前 openssl 不支持 -pbkdf2（需要 OpenSSL >= 1.1.1；LibreSSL 不支持）。
  解决：升级 openssl，或改用 python3 llm_probe.py（装了 cryptography 模块就不依赖 openssl）。"
    fi
}

# 口令只活在这个局部变量里，**绝不 export**：一旦 export，后续每个子进程
# （curl、openssl、被调起的任何程序）都会无条件继承它，等于把口令广播出去。
# openssl 需要它时用 `VAR=val cmd` 形式只喂给那一条命令。
need_passphrase() {  # $1 = 是否要求确认输入（confirm）
    PASSPHRASE=""
    if [ -n "$PASSPHRASE_ARG" ]; then
        PASSPHRASE=$PASSPHRASE_ARG
        warn_secret_arg "--passphrase"
    elif [ -n "${LLM_PASSPHRASE:-}" ]; then
        PASSPHRASE=$LLM_PASSPHRASE
        # 环境变量会被子进程继承，读到就摘掉
        unset LLM_PASSPHRASE
    elif [ -n "${PASSPHRASE_FILE:-}" ] && [ -f "$PASSPHRASE_FILE" ]; then
        PASSPHRASE=$(head -n 1 "$PASSPHRASE_FILE")
    elif [ -t 0 ]; then
        printf '解密口令: ' >&2
        stty -echo 2>/dev/null || true
        read -r PASSPHRASE
        stty echo 2>/dev/null || true
        printf '\n' >&2
        if [ "$1" = "confirm" ]; then
            printf '再输一次: ' >&2
            stty -echo 2>/dev/null || true
            read -r again
            stty echo 2>/dev/null || true
            printf '\n' >&2
            [ "$PASSPHRASE" = "$again" ] || die "两次输入的口令不一致"
        fi
    else
        die "拿不到解密口令，按推荐顺序任选其一：
  1) LLM_PASSPHRASE_FILE 指向口令文件（chmod 600，非交互场景首选）
  2) 在终端交互输入（最安全）
  3) 环境变量 LLM_PASSPHRASE（权宜之计：环境变量会被子进程继承，见 README 权衡表）"
    fi
    [ -n "$PASSPHRASE" ] || die "口令为空"
}

encrypt_key() {  # stdin → enc:v1:...
    # 口令只出现在这一条命令的环境里（VAR=val cmd，不 export）：
    # 既不进 ps 参数列表，也不被其它子进程继承。
    LLM_PASSPHRASE=$PASSPHRASE openssl enc -aes-256-cbc -pbkdf2 -iter "$PBKDF2_ITER" \
        -md sha256 -salt -pass env:LLM_PASSPHRASE 2>/dev/null | openssl base64 -A
}

decrypt_key() {  # $1 = enc:v1:... → stdout 明文
    # 常被 $( ) 子 shell 调用，这里不能 die（会只死子 shell），由调用方先 require_openssl
    case $1 in
        "$ENC_PREFIX"*) ;;
        *) return 1 ;;
    esac
    printf '%s' "${1#"$ENC_PREFIX"}" \
        | openssl base64 -d -A 2>/dev/null \
        | LLM_PASSPHRASE=$PASSPHRASE openssl enc -d -aes-256-cbc -pbkdf2 -iter "$PBKDF2_ITER" \
            -md sha256 -pass env:LLM_PASSPHRASE 2>/dev/null
}

mask_key() {
    key=$1
    len=$(printf '%s' "$key" | wc -c)
    if [ -z "$key" ]; then
        printf '(空)'
    elif [ "$len" -le 10 ]; then
        printf '%s' "$key" | sed 's/./*/g'
    else
        head=$(printf '%s' "$key" | cut -c1-6)
        tail=$(printf '%s' "$key" | rev | cut -c1-4 | rev)
        printf '%s********%s (len=%s)' "$head" "$tail" "$len"
    fi
}

resolve_key() {
    if [ -n "$KEY" ]; then
        warn_secret_arg "--key"
        unset LLM_API_KEY     # --key 已给定，环境里那份多余：同样摘掉
        KEY_SOURCE="--key 参数"
        return 0
    fi
    if [ -n "${LLM_API_KEY:-}" ]; then
        KEY=$LLM_API_KEY
        # 读到就摘：环境变量会被后续每个子进程无条件继承
        unset LLM_API_KEY
        KEY_SOURCE="环境变量 LLM_API_KEY"
        return 0
    fi
    if [ -n "$API_KEY_ENC" ]; then
        require_openssl
        need_passphrase ""
        if ! KEY=$(decrypt_key "$API_KEY_ENC"); then
            die "解密失败：口令错误，或密文损坏"
        fi
        KEY_SOURCE="配置文件（已解密）"
        return 0
    fi
    if [ -n "$API_KEY_PLAIN" ]; then
        KEY=$API_KEY_PLAIN
        KEY_SOURCE="配置文件明文 LLM_API_KEY"
        return 0
    fi
    KEY=""
    KEY_SOURCE="未提供（将只做匿名探测）"
}

# ---------------------------------------------------------------------------
# 探测
# ---------------------------------------------------------------------------
CURL_AUTH_UNUSED=0
curl_common() {  # 输出 curl 的公共参数（$1 = 超时）
    if [ "$DIRECT" = "1" ]; then
        printf '%s\n' "--noproxy" "*"
    fi
    printf '%s\n' "--silent" "--show-error" "--connect-timeout" "$1" "--max-time" "$1"
}

probe_net() {  # L1: DNS + TCP + TLS
    opts=$(curl_common "$TIMEOUT")
    # shellcheck disable=SC2086
    set -- $opts
    err=$(curl "$@" -o /dev/null \
        -w '%{time_connect} %{time_appconnect} %{remote_ip}' \
        "$BASE_URL/" 2>"$ERR_FILE")
    rc=$?
    if [ $rc -ne 0 ]; then
        classify_curl_error
        STEP1_OK=0
        STEP1_KIND=$CLASSIFY_KIND
        STEP1_DETAIL=$LAST_CURL_MSG
        return
    fi
    t_connect=$(printf '%s' "$err" | awk '{print $1}')
    t_tls=$(printf '%s' "$err" | awk '{print $2}')
    ip=$(printf '%s' "$err" | awk '{print $3}')
    ms=$(awk -v a="$t_connect" -v b="$t_tls" 'BEGIN{ t=(b>0?b:a)*1000; printf "%.1f", t }')
    STEP1_OK=1
    STEP1_KIND=""
    STEP1_DETAIL="DNS+TCP+TLS OK (${ms}ms) $ip（耗时: 连接 ${t_connect}s / 握手 ${t_tls}s）"
}

write_auth_header() {
    : > "$HEADER_FILE"
    if [ -n "$KEY" ]; then
        printf 'Authorization: Bearer %s\n' "$KEY" > "$HEADER_FILE"
    fi
}

probe_auth() {  # L2: GET /models
    STEP2_RAN=1
    opts=$(curl_common "$TIMEOUT")
    # shellcheck disable=SC2086
    set -- $opts
    if [ -n "$KEY" ]; then
        write_auth_header
        out=$(curl "$@" --header "@$HEADER_FILE" -H "Accept: application/json" \
            -o "$BODY_FILE" -w '%{http_code} %{time_total}' "$BASE_URL/models" 2>"$ERR_FILE")
    else
        out=$(curl "$@" -H "Accept: application/json" \
            -o "$BODY_FILE" -w '%{http_code} %{time_total}' "$BASE_URL/models" 2>"$ERR_FILE")
    fi
    rc=$?
    if [ $rc -ne 0 ]; then
        STEP2_OK=0; STEP2_FATAL=1
        classify_curl_error   # 注意：不能写成 $(...)，那样赋值会丢在子 shell 里
        STEP2_KIND=$CLASSIFY_KIND
        STEP2_DETAIL=$LAST_CURL_MSG
        return
    fi
    code=${out%% *}
    ms=$(ms_of "${out##* }")
    msg=$(extract_message)
    case $code in
        200)
            count=$(grep -o '"object"[[:space:]]*:[[:space:]]*"model"' "$BODY_FILE" | wc -l | tr -d ' ')
            STEP2_OK=1; STEP2_FATAL=1; STEP2_KIND=""
            STEP2_DETAIL="HTTP 200，可枚举模型 ${count:-0} 个 (${ms}ms)" ;;
        401|403)
            STEP2_OK=0; STEP2_FATAL=1; STEP2_KIND="auth"
            STEP2_DETAIL="HTTP $code：${msg:-密钥无效}" ;;
        404)
            STEP2_OK=0; STEP2_FATAL=0; STEP2_KIND="notfound"
            STEP2_DETAIL="HTTP 404：${msg:-该端点未实现 /models}（不代表 key 无效）" ;;
        429)
            STEP2_OK=0; STEP2_FATAL=1; STEP2_KIND="ratelimit"
            STEP2_DETAIL="HTTP 429：${msg:-限流 / 额度耗尽}" ;;
        *)
            STEP2_OK=0; STEP2_FATAL=1
            STEP2_KIND=$([ "$code" -ge 500 ] && echo server || echo client)
            STEP2_DETAIL="HTTP $code：${msg:-异常响应}" ;;
    esac
}

probe_infer() {  # L3: POST /chat/completions
    opts=$(curl_common "$TIMEOUT")
    # shellcheck disable=SC2086
    set -- $opts
    payload=$(printf '{"model":"%s","messages":[{"role":"user","content":"%s"}],"max_tokens":%s}' \
        "$(json_escape "$MODEL")" "$(json_escape "$PROMPT")" "$MAX_TOKENS")
    if [ -n "$KEY" ]; then
        write_auth_header
        out=$(curl "$@" --header "@$HEADER_FILE" -H "Content-Type: application/json" \
            -H "Accept: application/json" -d "$payload" \
            -o "$BODY_FILE" -w '%{http_code} %{time_total}' "$BASE_URL/chat/completions" 2>"$ERR_FILE")
    else
        out=$(curl "$@" -H "Content-Type: application/json" \
            -H "Accept: application/json" -d "$payload" \
            -o "$BODY_FILE" -w '%{http_code} %{time_total}' "$BASE_URL/chat/completions" 2>"$ERR_FILE")
    fi
    rc=$?
    if [ $rc -ne 0 ]; then
        STEP3_OK=0
        classify_curl_error   # 必须直接调用，$(...) 子 shell 会丢掉赋值
        STEP3_KIND=$CLASSIFY_KIND
        STEP3_DETAIL=$LAST_CURL_MSG
        return
    fi
    code=${out%% *}
    ms=$(ms_of "${out##* }")
    msg=$(extract_message)
    case $code in
        200)
            content=$(extract_content)
            usage=$(extract_usage)
            [ -n "$usage" ] || usage="?/?"     # 与 llm_probe.py 的文案形状保持一致
            STEP3_OK=1; STEP3_KIND=""
            STEP3_DETAIL="HTTP 200 (${ms}ms) model=$MODEL tokens=$usage"
            STEP3_CONTENT=$content ;;
        401|403) STEP3_OK=0; STEP3_KIND="auth";      STEP3_DETAIL="HTTP $code：${msg:-密钥无效}" ;;
        404)     STEP3_OK=0; STEP3_KIND="notfound";  STEP3_DETAIL="HTTP 404：${msg:-路径不对}" ;;
        400)     STEP3_OK=0; STEP3_KIND="badrequest";STEP3_DETAIL="HTTP 400：${msg:-请求参数不被接受}" ;;
        429)     STEP3_OK=0; STEP3_KIND="ratelimit"; STEP3_DETAIL="HTTP 429：${msg:-限流 / 额度耗尽}" ;;
        *)       STEP3_OK=0
                 STEP3_KIND=$([ "$code" -ge 500 ] && echo server || echo client)
                 STEP3_DETAIL="HTTP $code：${msg:-推理失败}" ;;
    esac
}

classify_curl_error() {  # 设置 LAST_CURL_MSG 与 CLASSIFY_KIND（勿在子 shell 中调用）
    msg=$(tr -d '\n' < "$ERR_FILE")
    LAST_CURL_MSG="网络错误: $msg"
    CLASSIFY_KIND="net"
    case $msg in
        *"Could not resolve"*)
            LAST_CURL_MSG="DNS 解析失败（域名不存在或无网络）"; CLASSIFY_KIND="dns" ;;
        *"Connection refused"*)
            LAST_CURL_MSG="连接被拒绝（端口没开）"; CLASSIFY_KIND="refused" ;;
        *"timed out"*|*"Timeout"*)
            LAST_CURL_MSG="请求超时"; CLASSIFY_KIND="timeout" ;;
        *"unexpected eof"*|*"Connection reset"*|*"Broken pipe"*)
            LAST_CURL_MSG="连接被重置（代理/防火墙中途掐断）: $msg"; CLASSIFY_KIND="net" ;;
        *"SSL"*|*"TLS"*|*"certificate"*|*"handshake"*)
            LAST_CURL_MSG="TLS 失败: $msg"; CLASSIFY_KIND="tls" ;;
        *"proxy"*)
            LAST_CURL_MSG="代理错误: $msg"; CLASSIFY_KIND="net" ;;
    esac
}

json_escape() {
    # JSON 字符串转义；逐字符处理，避免 awk gsub 对连续反斜杠的折叠。
    printf '%s' "$1" | awk '
        BEGIN { tab = sprintf("%c", 9); cr = sprintf("%c", 13) }
        {
            if (NR > 1) printf "\\n"
            for (i = 1; i <= length($0); i++) {
                c = substr($0, i, 1)
                if (c == "\\") printf "\\\\"
                else if (c == "\"") printf "\\\""
                else if (c == tab) printf "\\t"
                else if (c == cr) printf "\\r"
                else printf "%s", c
            }
        }
    '
}

json_unescape() {  # JSON 字符串里的 \uXXXX 解码；没有 python3 就原样返回
    case $1 in
        *'\u'*) ;;
        *) printf '%s' "$1"; return 0 ;;
    esac
    if command -v python3 >/dev/null 2>&1; then
        printf '%s' "$1" | python3 -c 'import sys, json
s = sys.stdin.read()
try:
    s = json.loads(chr(34) + s + chr(34))
except Exception:
    pass
sys.stdout.write(s)' 2>/dev/null || printf '%s' "$1"
    else
        printf '%s' "$1"
    fi
}

extract_message() {
    raw=$(sed -n 's/.*"message"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$BODY_FILE" 2>/dev/null | head -n 1)
    json_unescape "$raw"
}

extract_content() {
    raw=$(sed -n 's/.*"content"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$BODY_FILE" 2>/dev/null | head -n 1)
    json_unescape "$raw"
}

extract_usage() {  # 输出 "prompt/completion"（如 7/11）；响应里没有 usage 就输出空
    p=$(sed -n 's/.*"prompt_tokens"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p' "$BODY_FILE" 2>/dev/null | head -n 1)
    c=$(sed -n 's/.*"completion_tokens"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p' "$BODY_FILE" 2>/dev/null | head -n 1)
    if [ -n "$p" ] && [ -n "$c" ]; then
        printf '%s/%s' "$p" "$c"
    fi
}

ms_of() {  # 秒 → 毫秒（一位小数）
    awk -v s="$1" 'BEGIN{printf "%.1f", s*1000}'
}

# ---------------------------------------------------------------------------
# OpenAI compatibility matrix（显式 --matrix 才执行）
# ---------------------------------------------------------------------------
MATRIX_IDS="chat_completions responses_api streaming_sse tool_calling json_schema"
MATRIX_MAX_BODY_BYTES=2097152
MATRIX_MAX_BODY_BLOCKS=4096
MATRIX_CUR_ID=""
MATRIX_CUR_NAME=""
MATRIX_CUR_OK=false
MATRIX_CUR_SKIPPED=false
MATRIX_CUR_SUPPORTED=null
MATRIX_CUR_STATUS=0
MATRIX_CUR_KIND=null
MATRIX_CUR_MS=0.0
MATRIX_CUR_DETAIL=""

matrix_name() {
    case $1 in
        chat_completions) printf '%s' "Chat Completions" ;;
        responses_api) printf '%s' "Responses API" ;;
        streaming_sse) printf '%s' "Streaming SSE" ;;
        tool_calling) printf '%s' "Tool Calling" ;;
        json_schema) printf '%s' "JSON Schema" ;;
        *) printf '%s' "$1" ;;
    esac
}

matrix_set_row() {  # $1 id $2 ok $3 skipped $4 supported $5 status $6 kind $7 ms $8 detail
    MATRIX_CUR_ID=$1
    MATRIX_CUR_NAME=$(matrix_name "$1")
    MATRIX_CUR_OK=$2
    MATRIX_CUR_SKIPPED=$3
    MATRIX_CUR_SUPPORTED=$4
    MATRIX_CUR_STATUS=$5
    MATRIX_CUR_KIND=$6
    MATRIX_CUR_MS=$7
    MATRIX_CUR_DETAIL=$8
}

matrix_save_row() {
    # 详情不写入原始响应；去掉 tab/换行，保证 POSIX read 的字段稳定。
    detail=$(printf '%s' "$MATRIX_CUR_DETAIL" | tr '\t\r\n' '   ')
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$MATRIX_CUR_ID" "$MATRIX_CUR_NAME" "$MATRIX_CUR_OK" "$MATRIX_CUR_SKIPPED" \
        "$MATRIX_CUR_SUPPORTED" "$MATRIX_CUR_STATUS" "$MATRIX_CUR_KIND" \
        "$MATRIX_CUR_MS" "$detail" > "$TMP_DIR/matrix.$MATRIX_CUR_ID"
}

matrix_skip() {  # $1 id $2 detail $3 kind
    matrix_set_row "$1" false true null 0 "${3:-null}" 0.0 \
        "${2:-前置能力失败，已跳过（--all 可强制执行）}"
    matrix_save_row
}

matrix_network_detail() {
    case $1 in
        dns) printf '%s' "DNS 解析失败（域名不存在或无网络）" ;;
        timeout) printf '%s' "请求超时" ;;
        refused) printf '%s' "连接被拒绝（端口没开）" ;;
        tls) printf '%s' "TLS 失败" ;;
        *) printf '%s' "网络错误" ;;
    esac
}

matrix_http() {  # $1 url $2 payload $3 stream(0/1)
    matrix_url=$1
    matrix_request_payload=$2
    matrix_stream=${3:-0}
    : > "$BODY_FILE"
    : > "$ERR_FILE"
    : > "$HEAD_FILE"
    opts=$(curl_common "$TIMEOUT")
    # shellcheck disable=SC2086
    set -- $opts
    set -- "$@" --max-filesize "$MATRIX_MAX_BODY_BYTES"
    if [ "$matrix_stream" = "1" ]; then
        set -- "$@" --no-buffer
    fi
    if [ "$matrix_stream" = "1" ]; then
        accept="Accept: text/event-stream"
    else
        accept="Accept: application/json"
    fi
    # shellcheck disable=SC2086
    if [ -n "$KEY" ]; then
        write_auth_header
        out=$(
            ulimit -f "$MATRIX_MAX_BODY_BLOCKS" 2>/dev/null || exit 126
            curl "$@" -D "$HEAD_FILE" --header "@$HEADER_FILE" \
                -H "Content-Type: application/json" -H "$accept" -d "$matrix_request_payload" \
                -o "$BODY_FILE" -w '%{http_code} %{time_total}' "$matrix_url"
        ) 2>"$ERR_FILE"
    else
        out=$(
            ulimit -f "$MATRIX_MAX_BODY_BLOCKS" 2>/dev/null || exit 126
            curl "$@" -D "$HEAD_FILE" -H "Content-Type: application/json" \
                -H "$accept" -d "$matrix_request_payload" -o "$BODY_FILE" \
                -w '%{http_code} %{time_total}' "$matrix_url"
        ) 2>"$ERR_FILE"
    fi
    rc=$?
    body_bytes=$(wc -c < "$BODY_FILE" | tr -d '[:space:]')
    if [ $rc -ne 0 ]; then
        if [ "$rc" -eq 63 ] || [ "$body_bytes" -ge "$MATRIX_MAX_BODY_BYTES" ] \
            || grep -Eiq 'file.*(large|limit)|maximum file size' "$ERR_FILE"; then
            MATRIX_CUR_OK=false
            MATRIX_CUR_SKIPPED=false
            MATRIX_CUR_SUPPORTED=false
            matrix_status=${out%% *}
            case $matrix_status in
                ''|*[!0-9]*) matrix_status=0 ;;
            esac
            MATRIX_CUR_STATUS=$matrix_status
            MATRIX_CUR_KIND=malformed
            MATRIX_CUR_MS=0.0
            if [ "$MATRIX_CUR_STATUS" = "200" ]; then
                MATRIX_CUR_DETAIL="HTTP 200 但响应体超过大小上限"
            else
                MATRIX_CUR_DETAIL="HTTP ${MATRIX_CUR_STATUS:-0} 但响应体超过大小上限"
            fi
            return 1
        fi
        classify_curl_error
        MATRIX_CUR_OK=false
        MATRIX_CUR_SKIPPED=false
        MATRIX_CUR_SUPPORTED=null
        MATRIX_CUR_STATUS=0
        MATRIX_CUR_KIND=$CLASSIFY_KIND
        MATRIX_CUR_MS=0.0
        MATRIX_CUR_DETAIL=$(matrix_network_detail "$CLASSIFY_KIND")
        return 1
    fi
    if [ "$body_bytes" -ge "$MATRIX_MAX_BODY_BYTES" ]; then
        MATRIX_CUR_OK=false
        MATRIX_CUR_SKIPPED=false
        MATRIX_CUR_SUPPORTED=false
        matrix_status=${out%% *}
        case $matrix_status in
            ''|*[!0-9]*) matrix_status=0 ;;
        esac
        MATRIX_CUR_STATUS=$matrix_status
        MATRIX_CUR_KIND=malformed
        MATRIX_CUR_MS=$(ms_of "${out##* }")
        MATRIX_CUR_DETAIL="HTTP ${MATRIX_CUR_STATUS:-0} 但响应体超过大小上限"
        return 1
    fi
    MATRIX_CUR_STATUS=${out%% *}
    MATRIX_CUR_MS=$(ms_of "${out##* }")
    MATRIX_CUR_OK=false
    MATRIX_CUR_SKIPPED=false
    MATRIX_CUR_SUPPORTED=null
    MATRIX_CUR_KIND=null
    return 0
}

matrix_http_failure() {
    MATRIX_CUR_OK=false
    MATRIX_CUR_SKIPPED=false
    MATRIX_CUR_SUPPORTED=false
    case $MATRIX_CUR_STATUS in
        401|403) MATRIX_CUR_KIND=auth; MATRIX_CUR_SUPPORTED=null; MATRIX_CUR_DETAIL="HTTP $MATRIX_CUR_STATUS：认证失败" ;;
        3??) MATRIX_CUR_KIND=redirect; MATRIX_CUR_DETAIL="HTTP $MATRIX_CUR_STATUS：拒绝重定向" ;;
        404|405) MATRIX_CUR_KIND=unsupported; MATRIX_CUR_DETAIL="HTTP $MATRIX_CUR_STATUS：该能力未实现或路径不支持" ;;
        400) MATRIX_CUR_KIND=badrequest; MATRIX_CUR_DETAIL="HTTP 400：该能力不支持或请求被拒绝" ;;
        429) MATRIX_CUR_KIND=ratelimit; MATRIX_CUR_DETAIL="HTTP 429：限流 / 额度耗尽" ;;
        *) if [ "$MATRIX_CUR_STATUS" -ge 500 ] 2>/dev/null; then
                MATRIX_CUR_KIND=server; MATRIX_CUR_DETAIL="HTTP $MATRIX_CUR_STATUS：服务端错误"
            else
                MATRIX_CUR_KIND=client; MATRIX_CUR_DETAIL="HTTP $MATRIX_CUR_STATUS：异常响应"
            fi ;;
    esac
}

matrix_malformed() {
    MATRIX_CUR_OK=false
    MATRIX_CUR_SKIPPED=false
    MATRIX_CUR_SUPPORTED=false
    MATRIX_CUR_KIND=malformed
    MATRIX_CUR_DETAIL="HTTP 200 但响应格式不符合 OpenAI 兼容约定"
}

matrix_compact() {
    tr -d '[:space:]\\"' < "$BODY_FILE"
}

matrix_validate_chat() {
    if [ "$MATRIX_CUR_STATUS" != "200" ]; then matrix_http_failure; return; fi
    content=$(extract_content)
    compact=$(matrix_compact)
    if printf '%s' "$compact" | grep -Eq 'choices:\[\{.*message:\{.*content:[^,}]+' \
        && [ -n "$content" ]; then
        MATRIX_CUR_OK=true; MATRIX_CUR_SUPPORTED=true; MATRIX_CUR_KIND="null"
        MATRIX_CUR_DETAIL="HTTP 200，chat.completions 返回可解析回复"
    else
        matrix_malformed
    fi
}

matrix_validate_responses() {
    if [ "$MATRIX_CUR_STATUS" != "200" ]; then matrix_http_failure; return; fi
    compact=$(matrix_compact)
    response_shape=0
    if printf '%s' "$compact" | grep -Eq 'output:\[\{.*type:output_text,text:[^]]+\]'; then
        response_shape=1
    elif grep -Eq '"output_text"[[:space:]]*:[[:space:]]*"[^"]+"' "$BODY_FILE"; then
        response_shape=1
    fi
    if grep -Eq '"object"[[:space:]]*:[[:space:]]*"response"' "$BODY_FILE" \
        && grep -Eq '"status"[[:space:]]*:[[:space:]]*"completed"' "$BODY_FILE" \
        && [ "$response_shape" -eq 1 ]; then
        MATRIX_CUR_OK=true; MATRIX_CUR_SUPPORTED=true; MATRIX_CUR_KIND="null"
        MATRIX_CUR_DETAIL="HTTP 200，Responses API 返回可解析输出"
    else
        matrix_malformed
    fi
}

matrix_validate_sse() {
    if [ "$MATRIX_CUR_STATUS" != "200" ]; then matrix_http_failure; return; fi
    if ! grep -Eiq '^content-type:[[:space:]]*text/event-stream([[:space:]]*;|[[:space:]]*$)' "$HEAD_FILE" \
        || ! grep -Eq '^[[:space:]]*data:[[:space:]]*\{' "$BODY_FILE" \
        || ! grep -Eq '"object"[[:space:]]*:[[:space:]]*"chat.completion.chunk"' "$BODY_FILE" \
        || ! grep -Eq '^[[:space:]]*data:[[:space:]]*\[DONE\][[:space:]]*$' "$BODY_FILE" \
        || ! grep -Eq '"content"[[:space:]]*:[[:space:]]*"[^"]+"' "$BODY_FILE"; then
        matrix_malformed
        return
    fi
    MATRIX_CUR_OK=true; MATRIX_CUR_SUPPORTED=true; MATRIX_CUR_KIND="null"
    MATRIX_CUR_DETAIL="HTTP 200，SSE 事件与 [DONE] 完整"
}

matrix_validate_tools() {
    if [ "$MATRIX_CUR_STATUS" != "200" ]; then matrix_http_failure; return; fi
    compact=$(matrix_compact)
    if grep -Eq '"finish_reason"[[:space:]]*:[[:space:]]*"tool_calls"' "$BODY_FILE" \
        && grep -Eq '"tool_calls"[[:space:]]*:[[:space:]]*\[[[:space:]]*\{' "$BODY_FILE" \
        && grep -Eq '"name"[[:space:]]*:[[:space:]]*"llm_probe_lookup"' "$BODY_FILE" \
        && grep -Eq '"arguments"[[:space:]]*:[[:space:]]*"' "$BODY_FILE" \
        && printf '%s' "$compact" | grep -Eq 'tool_calls:\[\{[^}]*id:[^,}]+' \
        && printf '%s' "$compact" | grep -Eq 'tool_calls:\[\{.*function:\{.*arguments:\{city:Paris\}'; then
        MATRIX_CUR_OK=true; MATRIX_CUR_SUPPORTED=true; MATRIX_CUR_KIND="null"
        MATRIX_CUR_DETAIL="HTTP 200，tool_calls、arguments 与 finish_reason 有效"
    else
        matrix_malformed
    fi
}

matrix_validate_schema() {
    if [ "$MATRIX_CUR_STATUS" != "200" ]; then matrix_http_failure; return; fi
    # 固定 schema 只有 status=ok；去掉 JSON 转义引号后仍要求完整对象，不能把 okay 当成 ok。
    compact=$(matrix_compact)
    if ! grep -q '```' "$BODY_FILE" \
        && grep -Eq '"content"[[:space:]]*:[[:space:]]*"' "$BODY_FILE" \
        && printf '%s' "$compact" | grep -Eq 'choices:\[\{.*message:\{.*content:\{status:ok\}'; then
        MATRIX_CUR_OK=true; MATRIX_CUR_SUPPORTED=true; MATRIX_CUR_KIND="null"
        MATRIX_CUR_DETAIL="HTTP 200，JSON Schema 输出符合约定"
    else
        matrix_malformed
    fi
}

matrix_payload() {  # $1 feature
    case $1 in
        chat_completions)
            printf '{"model":"%s","messages":[{"role":"user","content":"Reply with exactly OK."}],"max_tokens":%s,"temperature":0}' \
                "$(json_escape "$MODEL")" "$MAX_TOKENS" ;;
        responses_api)
            printf '{"model":"%s","input":"Reply with exactly OK.","max_output_tokens":%s,"temperature":0}' \
                "$(json_escape "$MODEL")" "$MAX_TOKENS" ;;
        streaming_sse)
            printf '{"model":"%s","messages":[{"role":"user","content":"Reply with exactly OK."}],"max_tokens":%s,"temperature":0,"stream":true}' \
                "$(json_escape "$MODEL")" "$MAX_TOKENS" ;;
        tool_calling)
            printf '{"model":"%s","messages":[{"role":"user","content":"Look up Paris using the tool."}],"max_tokens":%s,"temperature":0,"tools":[{"type":"function","function":{"name":"llm_probe_lookup","description":"Return the city for a fixed compatibility probe.","parameters":{"type":"object","properties":{"city":{"type":"string"}},"required":["city"],"additionalProperties":false}}}],"tool_choice":{"type":"function","function":{"name":"llm_probe_lookup"}}}' \
                "$(json_escape "$MODEL")" "$MAX_TOKENS" ;;
        json_schema)
            schema_prompt=$(json_escape 'Return exactly {"status":"ok"}.')
            printf '{"model":"%s","messages":[{"role":"user","content":"%s"}],"max_tokens":%s,"temperature":0,"response_format":{"type":"json_schema","json_schema":{"name":"llm_probe_result","strict":true,"schema":{"type":"object","properties":{"status":{"type":"string","enum":["ok"]}},"required":["status"],"additionalProperties":false}}}}' \
                "$(json_escape "$MODEL")" "$schema_prompt" "$MAX_TOKENS" ;;
    esac
}

matrix_run_feature() {  # $1 id
    matrix_base=$BASE_URL
    while [ "${matrix_base%/}" != "$matrix_base" ]; do
        matrix_base=${matrix_base%/}
    done
    case $1 in
        chat_completions) url="$matrix_base/chat/completions"; stream=0 ;;
        responses_api) url="$matrix_base/responses"; stream=0 ;;
        streaming_sse) url="$matrix_base/chat/completions"; stream=1 ;;
        tool_calling) url="$matrix_base/chat/completions"; stream=0 ;;
        json_schema) url="$matrix_base/chat/completions"; stream=0 ;;
        *) die "未知 matrix feature: $1" ;;
    esac
    payload=$(matrix_payload "$1")
    if matrix_http "$url" "$payload" "$stream"; then
        case $1 in
            chat_completions) matrix_validate_chat ;;
            responses_api) matrix_validate_responses ;;
            streaming_sse) matrix_validate_sse ;;
            tool_calling) matrix_validate_tools ;;
            json_schema) matrix_validate_schema ;;
        esac
    fi
    matrix_set_row "$1" "$MATRIX_CUR_OK" "$MATRIX_CUR_SKIPPED" \
        "$MATRIX_CUR_SUPPORTED" "$MATRIX_CUR_STATUS" "$MATRIX_CUR_KIND" \
        "$MATRIX_CUR_MS" "$MATRIX_CUR_DETAIL"
    matrix_save_row
}

matrix_aggregate() {
    MATRIX_PASSED=0; MATRIX_FAILED=0; MATRIX_SKIPPED=0
    MATRIX_NETWORK_FOUND=0; MATRIX_AUTH_FOUND=0; MATRIX_OTHER_FOUND=0
    MATRIX_SOFT_ONLY=1
    MATRIX_CHAT_OK=0
    MATRIX_FIRST_DETAIL=""; MATRIX_FIRST_ID=""; MATRIX_FAILED_IDS=""
    for id in $MATRIX_IDS; do
        [ -f "$TMP_DIR/matrix.$id" ] || continue
        IFS="$(printf '\t')" read -r row_id row_name row_ok row_skipped row_supported row_status row_kind row_ms row_detail \
            < "$TMP_DIR/matrix.$id"
        if [ "$row_id" = "chat_completions" ] && [ "$row_ok" = "true" ]; then
            MATRIX_CHAT_OK=1
        fi
        if [ "$row_skipped" = "true" ]; then
            MATRIX_SKIPPED=$((MATRIX_SKIPPED + 1))
            case $row_kind in
                dns|timeout|refused|tls|net)
                    MATRIX_NETWORK_FOUND=1
                    [ -n "$MATRIX_FIRST_ID" ] || { MATRIX_FIRST_ID=$row_id; MATRIX_FIRST_DETAIL=$row_detail; }
                    ;;
            esac
        elif [ "$row_ok" = "true" ]; then
            MATRIX_PASSED=$((MATRIX_PASSED + 1))
        else
            MATRIX_FAILED=$((MATRIX_FAILED + 1))
            [ -n "$MATRIX_FIRST_ID" ] || { MATRIX_FIRST_ID=$row_id; MATRIX_FIRST_DETAIL=$row_detail; }
            if [ -n "$MATRIX_FAILED_IDS" ]; then MATRIX_FAILED_IDS="${MATRIX_FAILED_IDS}、"; fi
            MATRIX_FAILED_IDS="${MATRIX_FAILED_IDS}${row_id}"
            case $row_kind in
                dns|timeout|refused|tls|net) MATRIX_NETWORK_FOUND=1 ;;
                auth) MATRIX_AUTH_FOUND=1 ;;
                unsupported) ;;
                badrequest) MATRIX_OTHER_FOUND=1; MATRIX_SOFT_ONLY=0 ;;
                *) MATRIX_OTHER_FOUND=1; MATRIX_SOFT_ONLY=0 ;;
            esac
        fi
    done
    if [ "$MATRIX_NETWORK_FOUND" -eq 1 ]; then
        MATRIX_EXIT=2
        MATRIX_VERDICT="网络不可达：$MATRIX_FIRST_DETAIL"
    elif [ "$MATRIX_AUTH_FOUND" -eq 1 ]; then
        MATRIX_EXIT=3
        MATRIX_VERDICT="认证失败：$MATRIX_FIRST_DETAIL"
    elif [ "$MATRIX_FAILED" -gt 0 ] && { [ "$MATRIX_OTHER_FOUND" -eq 1 ] || [ "$ALLOW_UNSUPPORTED" -eq 0 ] || [ "$MATRIX_CHAT_OK" -eq 0 ]; }; then
        MATRIX_EXIT=4
        MATRIX_VERDICT="兼容能力不通过：$MATRIX_FAILED_IDS"
    elif [ "$MATRIX_FAILED" -gt 0 ]; then
        MATRIX_EXIT=0
        MATRIX_VERDICT="兼容能力通过（未实现：$MATRIX_FAILED_IDS）"
    elif [ "$MATRIX_CHAT_OK" -eq 0 ]; then
        MATRIX_EXIT=4
        MATRIX_VERDICT="兼容能力不通过：chat_completions"
    else
        MATRIX_EXIT=0
        MATRIX_VERDICT="兼容能力通过：5 项"
    fi
}

matrix_json_bool() { [ "$1" = "true" ] && printf '%s' true || printf '%s' false; }
matrix_json_kind() { [ "$1" = "null" ] && printf '%s' null || printf '"%s"' "$(json_escape "$1")"; }

matrix_print_json() {
    if [ -f "$CONFIG" ]; then config_json="\"$(json_escape "$CONFIG")\""; else config_json=null; fi
    printf '{\n'
    printf '  "version": "%s",\n' "$VERSION"
    printf '  "mode": "compatibility",\n'
    printf '  "base_url": "%s",\n' "$(json_escape "$BASE_URL")"
    printf '  "model": "%s",\n' "$(json_escape "$MODEL")"
    printf '  "key_masked": "%s",\n' "$(json_escape "$(mask_key "$KEY")")"
    printf '  "key_source": "%s",\n' "$(json_escape "$KEY_SOURCE")"
    printf '  "config": %s,\n' "$config_json"
    printf '  "steps": [\n'
    first=1
    for id in $MATRIX_IDS; do
        [ -f "$TMP_DIR/matrix.$id" ] || continue
        IFS="$(printf '\t')" read -r row_id row_name row_ok row_skipped row_supported row_status row_kind row_ms row_detail \
            < "$TMP_DIR/matrix.$id"
        [ "$first" -eq 1 ] || printf ',\n'
        first=0
        printf '    {"id": "%s", "name": "%s", "ok": %s, "skipped": %s, "supported": %s, "status": %s, "kind": %s, "ms": %s, "detail": "%s"}' \
            "$(json_escape "$row_id")" "$(json_escape "$row_name")" \
            "$(matrix_json_bool "$row_ok")" "$(matrix_json_bool "$row_skipped")" \
            "$row_supported" "$row_status" "$(matrix_json_kind "$row_kind")" "$row_ms" "$(json_escape "$row_detail")"
    done
    printf '\n  ],\n'
    printf '  "summary": {"passed": %s, "failed": %s, "skipped": %s, "total": 5},\n' \
        "$MATRIX_PASSED" "$MATRIX_FAILED" "$MATRIX_SKIPPED"
    printf '  "verdict": "%s",\n' "$(json_escape "$MATRIX_VERDICT")"
    printf '  "exit_code": %s\n}\n' "$MATRIX_EXIT"
}

matrix_print_human() {
    printf '%s\n' "============================================================"
    printf '端点   : %s\n' "$BASE_URL"
    printf '模型   : %s\n' "$MODEL"
    printf '密钥   : %s  [%s]\n' "$(mask_key "$KEY")" "$KEY_SOURCE"
    printf '%s\n' "------------------------------------------------------------"
    n=1
    for id in $MATRIX_IDS; do
        [ -f "$TMP_DIR/matrix.$id" ] || continue
        IFS="$(printf '\t')" read -r row_id row_name row_ok row_skipped row_supported row_status row_kind row_ms row_detail \
            < "$TMP_DIR/matrix.$id"
        if [ "$row_skipped" = "true" ]; then mark="SKIP"
        elif [ "$row_ok" = "true" ]; then mark="OK  "
        else mark="FAIL"; fi
        printf '[%s] %s [%s/5]  %s\n' "$mark" "$row_name" "$n" "$row_detail"
        n=$((n + 1))
    done
    printf '%s\n' "------------------------------------------------------------"
    printf '矩阵   : %s 通过 / %s 失败 / %s 跳过 / 5 总计\n' \
        "$MATRIX_PASSED" "$MATRIX_FAILED" "$MATRIX_SKIPPED"
    if [ "$MATRIX_EXIT" -eq 0 ]; then mark="✅"; else mark="❌"; fi
    printf '结论 %s %s\n' "$mark" "$MATRIX_VERDICT"
    printf '退出码 %s\n' "$MATRIX_EXIT"
    printf '%s\n' "============================================================"
}

run_matrix() {
    [ -n "$BASE_URL" ] || die "缺少 base_url：用 --base-url 或在配置里填 LLM_BASE_URL"
    [ -n "$MODEL" ] || die "缺少模型名：用 --model 或在配置里填 LLM_MODEL"
    case $BASE_URL in
        http://*|https://*) ;;
        *) die "base_url 非法（需要 http(s)://host[/v1]）: $BASE_URL" ;;
    esac
    resolve_key
    init_tmpdir
    probe_net
    if [ "$STEP1_OK" -eq 0 ]; then
        for id in $MATRIX_IDS; do matrix_skip "$id" "$STEP1_DETAIL" "$STEP1_KIND"; done
    else
        gated=0
        for id in $MATRIX_IDS; do
            if [ "$gated" -eq 1 ] && [ "$ALL" -eq 0 ]; then
                matrix_skip "$id"
            else
                matrix_run_feature "$id"
                if [ "$ALL" -eq 0 ] && [ "$MATRIX_CUR_OK" = "false" ]; then
                    case $MATRIX_CUR_KIND in
                        dns|timeout|refused|tls|net|auth|ratelimit) gated=1 ;;
                    esac
                fi
            fi
        done
    fi
    matrix_aggregate
    if [ "$JSON" = "1" ]; then matrix_print_json; else matrix_print_human; fi
    return "$MATRIX_EXIT"
}

# ---------------------------------------------------------------------------
# 报告
# ---------------------------------------------------------------------------
run_probe() {
    [ -n "$BASE_URL" ] || die "缺少 base_url：用 --base-url 或在配置里填 LLM_BASE_URL"
    [ -n "$MODEL" ] || [ "$ONLY" = "net" ] || [ "$ONLY" = "auth" ] \
        || die "缺少模型名：用 --model 或在配置里填 LLM_MODEL"
    case $BASE_URL in
        http://*|https://*) ;;
        *) die "base_url 非法（需要 http(s)://host[/v1]）: $BASE_URL" ;;
    esac

    # 密钥按需解析：--only net 只测网络，不该被“拿不到解密口令”卡住
    if [ "$ONLY" = "net" ]; then
        KEY=""
        unset LLM_API_KEY   # 这条路径不读密钥，但环境里那份仍不能给子进程
        KEY_SOURCE="未读取（--only net 不需要密钥）"
    else
        resolve_key
    fi

    init_tmpdir

    STEP1_OK=0; STEP1_KIND=""; STEP1_DETAIL=""
    STEP2_OK=0; STEP2_FATAL=1; STEP2_KIND=""; STEP2_DETAIL=""
    STEP3_OK=0; STEP3_KIND=""; STEP3_DETAIL=""; STEP3_CONTENT=""
    STEP3_SKIPPED=0
    TOTAL=1

    probe_net
    if [ "$ONLY" != "infer" ]; then
        TOTAL=$((TOTAL + 1))
        probe_auth
    fi
    if [ "$ONLY" != "auth" ] && [ "$ONLY" != "net" ]; then
        TOTAL=$((TOTAL + 1))
        if [ "$STEP2_OK" -eq 0 ] && [ "$STEP2_FATAL" -eq 1 ] && [ "$ALL" -eq 0 ] \
            && [ "$ONLY" != "infer" ]; then
            STEP3_SKIPPED=1
            STEP3_DETAIL="L2 认证未通过，已跳过（--all 可强制执行）"
        else
            probe_infer
        fi
    fi

    EXIT_CODE=0
    verdict=""
    if [ "$STEP1_OK" -eq 0 ]; then
        EXIT_CODE=2; verdict="网络不可达：$STEP1_DETAIL"
    elif [ "$STEP2_RAN" -eq 1 ] && [ "$STEP2_OK" -eq 0 ] && [ "$STEP2_FATAL" -eq 1 ]; then
        case $STEP2_KIND in
            auth)      EXIT_CODE=3; verdict="认证失败：API Key 无效或已过期（$STEP2_DETAIL）" ;;
            ratelimit) EXIT_CODE=3; verdict="认证被拒：限流或额度耗尽（$STEP2_DETAIL）" ;;
            dns|timeout|refused|tls|net) EXIT_CODE=2; verdict="网络不可达：$STEP2_DETAIL" ;;
            *)         EXIT_CODE=3; verdict="认证环节异常：$STEP2_DETAIL" ;;
        esac
    elif [ "$STEP3_SKIPPED" -eq 0 ] && [ -n "$STEP3_DETAIL" ] && [ "$STEP3_OK" -eq 0 ]; then
        case $STEP3_KIND in
            auth)       EXIT_CODE=3; verdict="认证失败：$STEP3_DETAIL" ;;
            notfound)   EXIT_CODE=4; verdict="路径不对：$STEP3_DETAIL（检查 base_url 是否含 /v1）" ;;
            badrequest) EXIT_CODE=4; verdict="请求参数不被接受：$STEP3_DETAIL（多半是模型名不对）" ;;
            ratelimit)  EXIT_CODE=4; verdict="限流 / 额度耗尽：$STEP3_DETAIL" ;;
            dns|timeout|refused|tls|net) EXIT_CODE=2; verdict="网络不可达：$STEP3_DETAIL" ;;
            *)          EXIT_CODE=4; verdict="推理失败：$STEP3_DETAIL" ;;
        esac
    else
        parts=""
        if [ "$STEP3_SKIPPED" -eq 0 ] && [ "$STEP3_OK" -eq 1 ]; then parts="推理正常"; fi
        if [ "$STEP3_SKIPPED" -eq 1 ]; then parts="推理已跳过"; fi
        if [ "$ONLY" = "net" ]; then parts="推理未测"; fi
        if [ "$STEP2_RAN" -eq 1 ] && [ "$STEP2_OK" -eq 1 ]; then
            parts="${parts:+$parts；}认证通过"
        fi
        if [ "$STEP2_RAN" -eq 1 ] && [ "$STEP2_OK" -eq 0 ] && [ "$STEP2_FATAL" -eq 0 ]; then
            parts="${parts:+$parts；}认证跳过（$STEP2_DETAIL）"
        fi
        verdict="${parts:-未执行任何检查}"
    fi

    if [ "$JSON" = "1" ]; then
        printf '{\n'
        printf '  "version": "%s",\n' "$VERSION"
        printf '  "base_url": "%s",\n' "$(json_escape "$BASE_URL")"
        printf '  "model": "%s",\n' "$(json_escape "$MODEL")"
        printf '  "key_masked": "%s",\n' "$(json_escape "$(mask_key "$KEY")")"
        printf '  "key_source": "%s",\n' "$(json_escape "$KEY_SOURCE")"
        if [ -f "$CONFIG" ]; then
            printf '  "config": "%s",\n' "$(json_escape "$CONFIG")"
        else
            printf '  "config": null,\n'
        fi
        printf '  "steps": [\n'
        printf '    {"name": "L1 网络", "ok": %s, "detail": "%s"}' \
            "$([ "$STEP1_OK" -eq 1 ] && echo true || echo false)" "$(json_escape "$STEP1_DETAIL")"
        if [ "$ONLY" != "infer" ]; then
            printf ',\n    {"name": "L2 认证", "ok": %s, "detail": "%s"}' \
                "$([ "$STEP2_OK" -eq 1 ] && echo true || echo false)" "$(json_escape "$STEP2_DETAIL")"
        fi
        if [ "$ONLY" != "auth" ] && [ "$ONLY" != "net" ]; then
            printf ',\n    {"name": "L3 推理", "ok": %s, "skipped": %s, "detail": "%s"}' \
                "$([ "$STEP3_OK" -eq 1 ] && echo true || echo false)" \
                "$([ "$STEP3_SKIPPED" -eq 1 ] && echo true || echo false)" \
                "$(json_escape "$STEP3_DETAIL")"
        fi
        printf '\n  ],\n'
        printf '  "verdict": "%s",\n' "$(json_escape "$verdict")"
        printf '  "exit_code": %s\n}\n' "$EXIT_CODE"
        return "$EXIT_CODE"
    fi

    printf '%s\n' "============================================================"
    printf '端点   : %s\n' "$BASE_URL"
    printf '模型   : %s\n' "$MODEL"
    printf '密钥   : %s  [%s]\n' "$(mask_key "$KEY")" "$KEY_SOURCE"
    printf '%s\n' "------------------------------------------------------------"
    n=1
    if [ "$STEP1_OK" -eq 1 ]; then mark="OK  "; else mark="FAIL"; fi
    printf '[%s] L1 网络 [%s/%s]  %s\n' "$mark" "$n" "$TOTAL" "$STEP1_DETAIL"
    if [ "$ONLY" != "infer" ]; then
        n=$((n + 1))
        if [ "$STEP2_OK" -eq 1 ]; then mark="OK  "; else mark="FAIL"; fi
        printf '[%s] L2 认证 [%s/%s]  %s\n' "$mark" "$n" "$TOTAL" "$STEP2_DETAIL"
    fi
    if [ "$ONLY" != "auth" ] && [ "$ONLY" != "net" ]; then
        n=$((n + 1))
        if [ "$STEP3_SKIPPED" -eq 1 ]; then
            mark="SKIP"
        elif [ "$STEP3_OK" -eq 1 ]; then
            mark="OK  "
        else
            mark="FAIL"
        fi
        printf '[%s] L3 推理 [%s/%s]  %s\n' "$mark" "$n" "$TOTAL" "$STEP3_DETAIL"
        if [ -n "$STEP3_CONTENT" ]; then
            printf '          回复: %s\n' "$(printf '%s' "$STEP3_CONTENT" | cut -c1-200)"
        fi
    fi
    printf '%s\n' "------------------------------------------------------------"
    if [ "$EXIT_CODE" -eq 0 ]; then mark="✅"; else mark="❌"; fi
    printf '结论 %s %s\n' "$mark" "$verdict"
    printf '退出码 %s\n' "$EXIT_CODE"
    printf '%s\n' "============================================================"
    return "$EXIT_CODE"
}

# ---------------------------------------------------------------------------
# 子命令
# ---------------------------------------------------------------------------
do_init() {
    if [ -f "$CONFIG" ] && [ "$FORCE" -eq 0 ]; then
        printf '配置已存在，未覆盖: %s（要覆盖加 --force）\n' "$CONFIG"
        return 1
    fi
    write_template "$CONFIG"
    printf '已生成配置: %s（权限 600）\n' "$CONFIG"
    printf '下一步: %s setkey\n' "$PROG"
    return 0
}

do_setkey() {
    if [ ! -f "$CONFIG" ]; then
        do_init || return 1
    fi
    load_config
    [ -n "$KEY" ] && warn_secret_arg "--key"
    new_key=$KEY
    if [ -z "$new_key" ] && [ -n "${LLM_API_KEY:-}" ]; then
        new_key=$LLM_API_KEY
    fi
    # 选完就摘：来源是 --key 还是环境变量，都不留给子进程
    unset LLM_API_KEY
    if [ -z "$new_key" ]; then
        if [ -t 0 ]; then
            printf 'API Key: ' >&2
            stty -echo 2>/dev/null || true
            read -r new_key
            stty echo 2>/dev/null || true
            printf '\n' >&2
        else
            # 非交互：从 stdin 读（管道内容不进 argv、不进 shell 历史）。
            # 注意 `printf '%s' "$KEY" | setkey` 没有尾换行，read 会返回非 0
            # 但变量其实已经拿到了——不能只看 read 的返回值。
            new_key=""
            IFS= read -r new_key || true
            new_key=$(printf '%s' "$new_key" | head -n 1)
            [ -n "$new_key" ] || die "拿不到密钥。非交互环境建议从管道读:
  printf '%s' \"\$KEY\" | $PROG setkey
（或用 LLM_API_KEY 环境变量；--key 会留在 shell 历史和 ps 进程列表里）"
        fi
    fi
    [ -n "$new_key" ] || die "密钥为空"
    require_openssl
    need_passphrase confirm
    token=$(printf '%s' "$new_key" | encrypt_key)
    [ -n "$token" ] || die "加密失败（openssl 不可用？）"
    case $token in "$ENC_PREFIX"*) ;; *) token="$ENC_PREFIX$token" ;; esac
    set_config_value "LLM_API_KEY_ENC" "$token"
    set_config_value "LLM_API_KEY" ""
    printf '已加密写入: %s\n' "$CONFIG"
    printf '密钥       : %s\n' "$(mask_key "$new_key")"
    printf '密文       : %s...（共 %s 字符）\n' "$(printf '%s' "$token" | cut -c1-38)" "$(printf '%s' "$token" | wc -c)"
    printf '注意：口令不会保存在配置里，别忘了它——丢了就只能重新 setkey。\n'
    return 0
}

do_showkey() {
    [ -f "$CONFIG" ] || die "配置文件不存在: $CONFIG"
    load_config
    if [ -n "$API_KEY_ENC" ]; then
        require_openssl
        need_passphrase ""
        if ! plain=$(decrypt_key "$API_KEY_ENC"); then
            die "解密失败：口令错误，或密文损坏"
        fi
        if [ "$PLAIN" = "1" ]; then printf '%s\n' "$plain"; else mask_key "$plain"; printf '\n'; fi
        return 0
    elif [ -n "$API_KEY_PLAIN" ]; then
        printf '明文密钥: %s\n' "$(mask_key "$API_KEY_PLAIN")"
        return 0
    fi
    printf '配置里没有密钥\n' >&2
    return 1
}

do_env() {
    [ -f "$CONFIG" ] || die "配置文件不存在: $CONFIG"
    load_config
    [ -n "$KEY" ] && warn_secret_arg "--key"
    if [ -n "$API_KEY_ENC" ]; then
        if [ -n "${LLM_PASSPHRASE:-}" ] || [ -n "$PASSPHRASE_ARG" ] \
            || [ -n "${PASSPHRASE_FILE:-}" ] || [ -t 0 ]; then
            require_openssl
            need_passphrase ""
            KEY=$(decrypt_key "$API_KEY_ENC" 2>/dev/null) || KEY=""
            KEY_SOURCE="配置文件（已解密）"
        fi
    fi
    if [ -z "${KEY:-}" ] && [ -n "${LLM_API_KEY:-}" ]; then
        KEY=$LLM_API_KEY
        unset LLM_API_KEY   # 读到就摘：别让它跟着子进程走
        KEY_SOURCE="环境变量 LLM_API_KEY"
    fi
    printf '配置文件 : %s\n' "$CONFIG"
    printf '%-22s= %s\n' "LLM_BASE_URL" "${BASE_URL:-(未设置)}"
    printf '%-22s= %s\n' "LLM_MODEL" "${MODEL:-(未设置)}"
    printf '%-22s= %s\n' "LLM_TIMEOUT" "$TIMEOUT"
    printf '%-22s= %s\n' "LLM_PROMPT" "$PROMPT"
    printf '%-22s= %s\n' "LLM_MAX_TOKENS" "$MAX_TOKENS"
    printf '%-22s= %s\n' "LLM_PASSPHRASE_FILE" "${PASSPHRASE_FILE:-(未设置)}"
    printf '%-22s= %s  [%s]\n' "LLM_API_KEY" "$(mask_key "${KEY:-}")" "${KEY_SOURCE:-未读取}"
    printf '%-22s= %s\n' "LLM_API_KEY_ENC" "$(printf '%s' "$API_KEY_ENC" | cut -c1-32)${API_KEY_ENC:+...}"
    return 0
}

# ---------------------------------------------------------------------------
# 参数解析
# ---------------------------------------------------------------------------
parse_args() {
    CMD=""
    while [ $# -gt 0 ]; do
        case $1 in
            -c|--config) [ $# -ge 2 ] || die "缺少 $1 的值"; CONFIG=$2; shift 2 ;;
            --config=*)  CONFIG=${1#*=}; shift ;;
            --base-url)  [ $# -ge 2 ] || die "缺少 $1 的值"; BASE_URL_ARG=$2; shift 2 ;;
            --model)     [ $# -ge 2 ] || die "缺少 $1 的值"; MODEL_ARG=$2; shift 2 ;;
            --prompt)    [ $# -ge 2 ] || die "缺少 $1 的值"; PROMPT_ARG=$2; shift 2 ;;
            --timeout)   [ $# -ge 2 ] || die "缺少 $1 的值"; TIMEOUT_ARG=$2; shift 2 ;;
            --max-tokens)[ $# -ge 2 ] || die "缺少 $1 的值"; MAX_TOKENS_ARG=$2; shift 2 ;;
            --key)       [ $# -ge 2 ] || die "缺少 $1 的值"; KEY=$2; shift 2 ;;
            --passphrase)[ $# -ge 2 ] || die "缺少 $1 的值"; PASSPHRASE_ARG=$2; shift 2 ;;
            --only)      [ $# -ge 2 ] || die "缺少 $1 的值"; ONLY=$2; shift 2 ;;
            --all)       ALL=1; shift ;;
            --matrix)    MATRIX=1; shift ;;
            --allow-unsupported) ALLOW_UNSUPPORTED=1; shift ;;
            --direct)    DIRECT=1; shift ;;
            --json)      JSON=1; shift ;;
            --plain)     PLAIN=1; shift ;;
            --force)     FORCE=1; shift ;;
            probe|init|setkey|showkey|env)
                [ -z "$CMD" ] || die "多余的子命令: $1"
                CMD=$1; shift ;;
            help|-h|--help) usage 0 ;;
            -v|--version) printf '%s %s\n' "$PROG" "$VERSION"; exit 0 ;;
            --)          shift; break ;;
            *)           printf '未知参数: %s\n' "$1" >&2; usage 1 ;;
        esac
    done
    [ -n "$CMD" ] || CMD=probe
    case $ONLY in
        ""|net|auth|infer) ;;
        sdk) die "sh 版没有 openai SDK 层，请用: python3 llm_probe.py probe --sdk" ;;
        *)   die "--only 只接受 net / auth / infer" ;;
    esac
    if [ "$MATRIX" -eq 1 ] && [ -n "$ONLY" ]; then
        die "--matrix 不能与 --only 同时使用"
    fi
    if [ "$MATRIX" -eq 1 ] && [ "$CMD" != "probe" ]; then
        die "--matrix 只能与 probe 子命令一起使用"
    fi
    if [ "$ALLOW_UNSUPPORTED" -eq 1 ] && [ "$MATRIX" -ne 1 ]; then
        die "--allow-unsupported 只能与 --matrix 同时使用"
    fi
}

main() {
    BASE_URL_ARG=""; MODEL_ARG=""; PROMPT_ARG=""; TIMEOUT_ARG=""; MAX_TOKENS_ARG=""
    parse_args "$@"
    # 命令行参数 > 环境变量 > 配置文件
    load_config
    [ -n "$BASE_URL_ARG" ] && BASE_URL=$BASE_URL_ARG
    [ -n "$MODEL_ARG" ] && MODEL=$MODEL_ARG
    [ -n "$PROMPT_ARG" ] && PROMPT=$PROMPT_ARG
    [ -n "$TIMEOUT_ARG" ] && TIMEOUT=$TIMEOUT_ARG
    [ -n "$MAX_TOKENS_ARG" ] && MAX_TOKENS=$MAX_TOKENS_ARG
    validate_options    # CLI 值是刚套用的，必须在这里再校验一次

    case $CMD in
        probe)
            if [ "$MATRIX" -eq 1 ]; then run_matrix; else run_probe; fi
            ;;
        init)    do_init ;;
        setkey)  do_setkey ;;
        showkey) do_showkey ;;
        env)     do_env ;;
    esac
}

main "$@"
