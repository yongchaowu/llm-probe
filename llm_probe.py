#!/usr/bin/env python3
"""LLM 端点连通性探测：OpenAI 兼容 API 分层检查 + env 配置加密存储。

零第三方依赖（标准库 only），Python 3.7+。
姊妹脚本 llm_probe.sh 提供 curl/openssl 版本，二者读同一份配置、
用同一种密文格式，可以互相解密对方写入的 key。

子命令
------
  probe    分层探测端点连通性（默认动作）
  init     生成配置文件 .llm_probe.env
  setkey   加密写入 API Key（覆盖 LLM_API_KEY_ENC，清掉明文）
  showkey  解密显示 API Key（默认打码）
  env      打印生效配置（密钥打码）

分层探测
------
  L1 网络   DNS → TCP → TLS 握手
  L2 认证   GET  {base}/models
  L3 推理   POST {base}/chat/completions
  L4 SDK    真实 openai SDK 调用（--sdk 时执行，自动适配 0.x / 1.x）
  --matrix  显式验证 chat/responses/streaming/tools/json_schema 五项兼容能力

退出码
------
  0 全部通过   1 用法/配置错误   2 网络不通
  3 认证失败    4 推理失败        5 SDK 调用失败
"""

import argparse
import base64
import hashlib
import hmac
import json
import os
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

VERSION = "1.1"

# -- 加密参数：与 `openssl enc -aes-256-cbc -pbkdf2 -iter 300000 -md sha256`
#    完全对齐，保证 Python 和 shell 两端互认对方的密文 -----------------------
ENC_PREFIX = "enc:v1:"
PBKDF2_ITER = 300_000
SALT_LEN, KEY_LEN, IV_LEN = 8, 32, 16

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_CONFIG = os.path.join(SCRIPT_DIR, ".llm_probe.env")

ENV_TEMPLATE = """\
# llm_probe 配置文件（dotenv 风格）
# 注意：这是数据文件，不是 shell 脚本，任何一行都不会被当作命令执行。
#
# 生成本文件:  python3 llm_probe.py init
# 写入密钥:    python3 llm_probe.py setkey                  （交互输入，推荐）
#              printf '%s' "$KEY" | python3 llm_probe.py setkey   （非交互，走 stdin）
#              python3 llm_probe.py setkey --key sk-xxx       （会进 shell 历史 / ps，
#                                                              仅临时测试用）
# 查看密钥:    python3 llm_probe.py showkey
# 开始探测:    python3 llm_probe.py probe

# OpenAI 兼容端点，通常以 /v1 结尾。默认填官方地址；换服务商就改成它给的
# base_url。（README 里的 https://aiapiv2.pekpik.com/v1 是第三方中转示例，
# 别默认把密钥发给不认识的服务。）
LLM_BASE_URL=https://api.openai.com/v1

# 模型名按服务商自己的命名填
LLM_MODEL=gpt-4o-mini

# 加密后的密钥（enc:v1:... ），由 setkey 写入，不要手填
LLM_API_KEY_ENC=

# 明文密钥：仅用于临时调试。存在时优先级低于 LLM_API_KEY_ENC。
# 用 setkey 写入时会自动清空本行。
LLM_API_KEY=

# 解密口令来源（口令本身永远不写进本文件，否则加密就失去意义了）：
#   1) LLM_PASSPHRASE_FILE 指向的口令文件（建议 chmod 600，非交互首选）
#   2) 终端交互输入（最安全）
#   3) 环境变量 LLM_PASSPHRASE（权宜之计：环境变量会被子进程继承，
#      读到后本脚本会立即从环境里摘掉）
LLM_PASSPHRASE_FILE=

# 探测参数
LLM_TIMEOUT=30
LLM_PROMPT=你好
LLM_MAX_TOKENS=64
"""


# ---------------------------------------------------------------------------
# 配置文件读写
# ---------------------------------------------------------------------------
def parse_env_file(path):
    """解析 dotenv：只做 KEY=VALUE 切分，不执行任何内容。"""
    data = {}
    with open(path, "r", encoding="utf-8") as fh:
        for lineno, raw in enumerate(fh, 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                raise ValueError(f"{path}:{lineno}: 不是合法的 KEY=VALUE: {line!r}")
            key, _, value = line.partition("=")
            key = key.strip()
            if not key:
                raise ValueError(f"{path}:{lineno}: KEY 不能为空: {line!r}")
            value = value.strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
                value = value[1:-1]
            data[key] = value
    return data


def read_config(path):
    """读配置；格式错误变成人话 + 退出码 1，而不是甩一个 traceback。"""
    try:
        return parse_env_file(path)
    except ValueError as exc:
        print(f"配置文件格式错误: {exc}", file=sys.stderr)
        raise SystemExit(1)
    except OSError as exc:
        print(f"读不了配置文件 {path}: {exc}", file=sys.stderr)
        raise SystemExit(1)


def update_env_file(path, updates):
    """按行更新配置文件：已存在的 key 原地覆盖，缺失的追加，注释原样保留。"""
    lines = []
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as fh:
            lines = fh.read().splitlines()
    pending = dict(updates)
    for idx, line in enumerate(lines):
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key = stripped.partition("=")[0].strip()
        if key in pending:
            lines[idx] = f"{key}={pending.pop(key)}"
    for key, value in pending.items():
        lines.append(f"{key}={value}")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def init_config(path, force=False):
    if os.path.exists(path) and not force:
        print(f"配置已存在，未覆盖: {path}（要覆盖加 --force）")
        return 1
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(ENV_TEMPLATE)
    os.chmod(path, 0o600)
    print(f"已生成配置: {path}（权限 600）")
    print("下一步: python3 llm_probe.py setkey")
    return 0


# ---------------------------------------------------------------------------
# 密钥加密 / 解密
# ---------------------------------------------------------------------------
def _derive(salt, passphrase):
    """PBKDF2-HMAC-SHA256 派生 key+iv，等价 openssl 的 -pbkdf2 -iter 300000。"""
    material = hashlib.pbkdf2_hmac(
        "sha256", passphrase.encode("utf-8"), salt, PBKDF2_ITER, dklen=KEY_LEN + IV_LEN
    )
    return material[:KEY_LEN], material[KEY_LEN:]


def _pkcs7_pad(data):
    pad = IV_LEN - (len(data) % IV_LEN)
    return data + bytes([pad]) * pad


def _pkcs7_unpad(data):
    if not data or len(data) % IV_LEN:
        raise ValueError("密文长度非法")
    pad = data[-1]
    if pad < 1 or pad > IV_LEN or data[-pad:] != bytes([pad]) * pad:
        raise ValueError("填充校验失败")
    return data[:-pad]


_OPENSSL_PBKDF2_OK = None


def _openssl_pbkdf2_ok():
    """功能性探测 openssl 是否支持 -pbkdf2（OpenSSL >= 1.1.1；LibreSSL 不支持）。

    比读版本号可靠：LibreSSL 的版本号长成 3.x 却没有 -pbkdf2。
    """
    global _OPENSSL_PBKDF2_OK
    if _OPENSSL_PBKDF2_OK is not None:
        return _OPENSSL_PBKDF2_OK
    try:
        probe = subprocess.run(
            ["openssl", "enc", "-aes-256-cbc", "-pbkdf2", "-iter", "1000",
             "-md", "sha256", "-pass", "pass:probe", "-in", os.devnull],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        ok = probe.returncode == 0
    except OSError:
        ok = False
    _OPENSSL_PBKDF2_OK = ok
    return ok


def _require_openssl_pbkdf2():
    if not _openssl_pbkdf2_ok():
        raise ValueError(
            "这台机器的 openssl 不支持 -pbkdf2（需要 OpenSSL >= 1.1.1，LibreSSL 不支持），"
            "也未安装 cryptography 模块。解决：升级 openssl，或 pip install cryptography。"
        )


def _encrypt_openssl(plain, passphrase):
    _require_openssl_pbkdf2()
    """走 openssl CLI（无 cryptography 模块时的兜底，也是 shell 端的实现）。"""
    env = dict(os.environ, LLM_PP_PASSPHRASE=passphrase)
    proc = subprocess.run(
        [
            "openssl", "enc", "-aes-256-cbc", "-pbkdf2",
            "-iter", str(PBKDF2_ITER), "-md", "sha256", "-salt",
            "-pass", "env:LLM_PP_PASSPHRASE",
        ],
        input=plain.encode("utf-8"),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        check=True,
    )
    return proc.stdout


def _decrypt_openssl(blob, passphrase):
    _require_openssl_pbkdf2()
    env = dict(os.environ, LLM_PP_PASSPHRASE=passphrase)
    proc = subprocess.run(
        [
            "openssl", "enc", "-d", "-aes-256-cbc", "-pbkdf2",
            "-iter", str(PBKDF2_ITER), "-md", "sha256",
            "-pass", "env:LLM_PP_PASSPHRASE",
        ],
        input=blob,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
    )
    if proc.returncode != 0:
        raise ValueError("openssl 解密失败（口令错误？）")
    return proc.stdout


def _crypto_module():
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.primitives import padding  # noqa: F401  (需要时可用)
        return True
    except Exception:
        return False


def encrypt_secret(plain, passphrase):
    """加密为 enc:v1:<base64( "Salted__" + salt + 密文 )>。"""
    salt = os.urandom(SALT_LEN)
    key, iv = _derive(salt, passphrase)
    blob = None
    if _crypto_module():
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
        blob = encryptor.update(_pkcs7_pad(plain.encode("utf-8"))) + encryptor.finalize()
    else:
        blob = _encrypt_openssl(plain, passphrase)
        # openssl 自带 "Salted__"+salt 头，直接用它的输出
        return ENC_PREFIX + base64.b64encode(blob).decode("ascii")
    payload = b"Salted__" + salt + blob
    return ENC_PREFIX + base64.b64encode(payload).decode("ascii")


def decrypt_secret(token, passphrase):
    """解密 enc:v1:... ；兼容 openssl CLI 与本模块两种产出。"""
    if not token.startswith(ENC_PREFIX):
        raise ValueError("不是 enc:v1: 格式的密文")
    try:
        blob = base64.b64decode(token[len(ENC_PREFIX):], validate=True)
    except Exception as exc:
        raise ValueError(f"密文 base64 解码失败: {exc}")
    if blob[:8] != b"Salted__" or len(blob) < 16 + IV_LEN:
        # 不是 openssl 头格式，交给 openssl 处理
        return _decrypt_openssl(blob, passphrase).decode("utf-8")
    salt = blob[8:16]
    ct = blob[16:]
    key, iv = _derive(salt, passphrase)
    if _crypto_module():
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
        try:
            plain = decryptor.update(ct) + decryptor.finalize()
            return _pkcs7_unpad(plain).decode("utf-8")
        except Exception as exc:
            raise ValueError(f"解密失败（口令错误？）: {exc}")
    return _decrypt_openssl(blob, passphrase).decode("utf-8")


def mask_secret(secret):
    if not secret:
        return "(空)"
    if len(secret) <= 10:
        return "*" * len(secret)
    return f"{secret[:6]}{'*' * 8}{secret[-4:]} (len={len(secret)})"


def scrub_env(*names):
    """读完就把口令/密钥从本进程环境变量里摘掉。

    环境变量会被每个子进程无条件继承（curl、openssl、openai SDK，以及它们
    自己再拉起的进程），留在 os.environ 等于把密钥广播给整棵进程树。取值已经
    存进局部变量，后续逻辑不受影响。
    """
    for name in names:
        os.environ.pop(name, None)


def warn_secret_arg(flag):
    """命令行参数里的密钥会同时出现在 shell 历史和 ps 进程列表里。"""
    print(
        f"⚠ 警告: {flag} 会留在 shell 历史和进程列表 (ps) 里，"
        "仅建议临时测试用；日常请用交互输入、stdin 管道或环境变量。",
        file=sys.stderr,
    )


def read_passphrase(args, cfg, *, confirm=False, allow_prompt=True):
    """口令来源：--passphrase > LLM_PASSPHRASE 环境变量 > 口令文件 > 交互。

    三个来源的权衡见 README「口令从哪来」一节：
      * 口令文件  —— 非交互首选，chmod 600，不进进程环境
      * 交互输入 —— 最安全，只在内存里过一遍
      * 环境变量 —— 权宜之计；读到后立即摘掉，避免被子进程继承
    """
    if getattr(args, "passphrase", None):
        warn_secret_arg("--passphrase")
        return args.passphrase
    if os.environ.get("LLM_PASSPHRASE"):
        value = os.environ["LLM_PASSPHRASE"]
        scrub_env("LLM_PASSPHRASE", "LLM_PP_PASSPHRASE")
        return value
    passphrase_file = cfg.get("LLM_PASSPHRASE_FILE") or ""
    if passphrase_file:
        passphrase_file = os.path.expanduser(passphrase_file)
        if os.path.exists(passphrase_file):
            with open(passphrase_file, "r", encoding="utf-8") as fh:
                value = fh.read().strip()
            if value:
                return value
    if not allow_prompt or not sys.stdin.isatty():
        return None
    import getpass
    first = getpass.getpass("解密口令: ")
    if confirm:
        second = getpass.getpass("再输一次: ")
        if first != second:
            raise ValueError("两次输入的口令不一致")
    return first or None


# ---------------------------------------------------------------------------
# HTTP 基础设施
# ---------------------------------------------------------------------------
class _SameOriginRedirectHandler(urllib.request.HTTPRedirectHandler):
    """允许同源跳转，拒绝把 Authorization 转发到另一 origin。"""

    @staticmethod
    def _origin(url):
        parts = urllib.parse.urlsplit(url)
        port = parts.port or (443 if parts.scheme.lower() == "https" else 80)
        return parts.scheme.lower(), (parts.hostname or "").lower(), port

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if self._origin(req.full_url) != self._origin(newurl):
            return None
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_HTTP_OPENER_CONFIGURED = False


def install_http_opener(direct=False):
    """安装带同源重定向保护的 opener；direct 时同时禁用系统代理。"""
    global _HTTP_OPENER_CONFIGURED
    handlers = [_SameOriginRedirectHandler()]
    if direct:
        handlers.append(urllib.request.ProxyHandler({}))
    urllib.request.install_opener(urllib.request.build_opener(*handlers))
    _HTTP_OPENER_CONFIGURED = True


def classify_error(exc):
    """把异常翻译成人类能看懂的网络结论。"""
    if isinstance(exc, urllib.error.URLError):
        reason = exc.reason
        if isinstance(reason, socket.gaierror):
            return "dns", "DNS 解析失败（域名不存在或无网络）"
        if isinstance(reason, socket.timeout) or isinstance(exc, TimeoutError):
            return "timeout", "连接超时（被防火墙丢包或服务未监听）"
        if isinstance(reason, ConnectionRefusedError):
            return "refused", "连接被拒绝（端口没开）"
        if isinstance(reason, ssl.SSLError):
            return "tls", f"TLS 握手失败: {reason}"
        return "net", f"网络错误: {reason}"
    if isinstance(exc, TimeoutError):
        return "timeout", "请求超时"
    if isinstance(exc, ssl.SSLError):
        return "tls", f"TLS 错误: {exc}"
    if isinstance(exc, ConnectionRefusedError):
        return "refused", "连接被拒绝"
    return "net", f"{type(exc).__name__}: {exc}"


def http_call(url, method="GET", headers=None, payload=None, timeout=30, max_body_bytes=None):
    """发一次 HTTP 请求，永不抛异常，统一返回结构化结果。

    ``headers`` 被规范化为小写键名，兼容矩阵需要读取 Content-Type；普通 probe
    不依赖这个扩展字段，原有返回结构保持不变。``max_body_bytes`` 用于限制
    响应体，避免异常端点把探针变成无界内存消费者。
    """
    body = None
    if payload is not None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(url, data=body, method=method)
    for key, value in (headers or {}).items():
        req.add_header(key, value)
    start = time.monotonic()
    if not _HTTP_OPENER_CONFIGURED:
        install_http_opener()

    def read_body(response):
        if max_body_bytes is None:
            return response.read(), False
        raw = response.read(max_body_bytes + 1)
        return raw[:max_body_bytes], len(raw) > max_body_bytes

    def response_headers(response):
        try:
            return {str(key).lower(): str(value) for key, value in response.getheaders()}
        except Exception:
            return {}

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw, truncated = read_body(resp)
            elapsed = round((time.monotonic() - start) * 1000, 1)
            return {
                "ok": not truncated, "status": getattr(resp, "status", resp.getcode()),
                "body": raw, "headers": response_headers(resp), "ms": elapsed,
                "error": {"kind": "body_too_large", "message": "响应体超过大小上限"}
                if truncated else None,
            }
    except urllib.error.HTTPError as exc:
        try:
            raw, truncated = read_body(exc)
        except Exception:
            raw, truncated = b"", False
        return {
            "ok": False, "status": exc.code, "body": raw,
            "headers": response_headers(exc),
            "ms": round((time.monotonic() - start) * 1000, 1),
            "error": {"kind": "body_too_large", "message": "响应体超过大小上限"}
            if truncated else None,
        }
    except Exception as exc:
        kind, message = classify_error(exc)
        return {
            "ok": False, "status": 0, "body": b"", "headers": {},
            "ms": round((time.monotonic() - start) * 1000, 1),
            "error": {"kind": kind, "message": message},
        }


def error_message(body):
    """从响应体里挖出服务端给出的错误说明。"""
    try:
        data = json.loads(body.decode("utf-8", "replace"))
    except Exception:
        text = body.decode("utf-8", "replace").strip()
        return text[:160] if text else ""
    err = data.get("error")
    if isinstance(err, dict):
        return str(err.get("message") or err.get("code") or "")
    if isinstance(err, str):
        return err
    if data.get("message"):
        return str(data["message"])
    return ""


# ---------------------------------------------------------------------------
# 分层探测
# ---------------------------------------------------------------------------
def step_network(base_url, timeout):
    parts = urllib.parse.urlsplit(base_url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        return {"name": "L1 网络", "ok": False,
                "detail": f"base_url 非法（需要 http(s)://host[/v1]）: {base_url!r}"}
    host = parts.hostname
    port = parts.port or (443 if parts.scheme == "https" else 80)

    start = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            tcp_ms = round((time.monotonic() - start) * 1000, 1)
            if parts.scheme != "https":
                return {"name": "L1 网络", "ok": True,
                        "detail": f"DNS+TCP {host}:{port} OK ({tcp_ms}ms, 明文 HTTP)"}
            context = ssl.create_default_context()
            with context.wrap_socket(sock, server_hostname=host) as tls:
                ms = round((time.monotonic() - start) * 1000, 1)
                cert = tls.getpeercert() or {}
                subject = dict(x[0] for x in cert.get("subject", ())).get("commonName", "?")
                not_after = cert.get("notAfter", "未知")
                return {"name": "L1 网络", "ok": True,
                        "detail": (f"DNS+TCP+TLS {host}:{port} OK ({ms}ms) "
                                   f"{tls.version()} CN={subject} 有效期至 {not_after}")}
    except Exception as exc:
        kind, message = classify_error(exc)
        return {"name": "L1 网络", "ok": False, "kind": kind, "detail": message}


def step_auth(base_url, key, timeout):
    url = base_url.rstrip("/") + "/models"
    headers = {"Accept": "application/json"}
    if key:
        headers["Authorization"] = f"Bearer {key}"
    result = http_call(url, "GET", headers, timeout=timeout)
    step = {"name": "L2 认证", "url": url, "status": result["status"],
            "ms": result["ms"], "error": result["error"]}
    if result["error"]:
        step.update(ok=False, kind=result["error"]["kind"], detail=result["error"]["message"])
        return step
    status = result["status"]
    message = error_message(result["body"])
    if status == 200:
        try:
            count = len(json.loads(result["body"]).get("data", []))
            detail = f"HTTP 200，可枚举模型 {count} 个"
        except Exception:
            detail = "HTTP 200"
        step.update(ok=True, detail=f"{detail} ({result['ms']}ms)")
    elif status in (401, 403):
        step.update(ok=False, kind="auth", detail=f"HTTP {status}：{message or '密钥无效'}")
    elif status == 404:
        step.update(ok=False, kind="notfound", fatal=False,
                    detail=f"HTTP 404：{message or '该端点未实现 /models'}（不代表 key 无效）")
    elif status == 429:
        step.update(ok=False, kind="ratelimit",
                    detail=f"HTTP 429：{message or '限流 / 额度耗尽'}")
    else:
        step.update(ok=False, kind="server" if status >= 500 else "client",
                    detail=f"HTTP {status}：{message or '异常响应'}")
    return step


def step_infer(base_url, key, model, prompt, max_tokens, timeout):
    url = base_url.rstrip("/") + "/chat/completions"
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    if key:
        headers["Authorization"] = f"Bearer {key}"
    payload = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": max_tokens,
    }
    result = http_call(url, "POST", headers, payload, timeout=timeout)
    step = {"name": "L3 推理", "url": url, "status": result["status"],
            "ms": result["ms"], "error": result["error"]}
    if result["error"]:
        step.update(ok=False, kind=result["error"]["kind"], detail=result["error"]["message"])
        return step
    status = result["status"]
    message = error_message(result["body"])
    if status != 200:
        kind = {401: "auth", 403: "auth", 404: "notfound", 429: "ratelimit",
                400: "badrequest", 404: "notfound"}.get(status,
                    "server" if status >= 500 else "client")
        step.update(ok=False, kind=kind, detail=f"HTTP {status}：{message or '推理失败'}")
        return step
    try:
        data = json.loads(result["body"])
        choice = (data.get("choices") or [{}])[0]
        content = (choice.get("message") or {}).get("content") or ""
        usage = data.get("usage") or {}
        detail = (f"HTTP 200 ({result['ms']}ms) model={data.get('model', model)} "
                  f"tokens={usage.get('prompt_tokens', '?')}/{usage.get('completion_tokens', '?')}")
        step.update(ok=True, detail=detail,
                    content=(content or "").strip(),
                    finish=(choice.get("finish_reason") or ""))
    except Exception as exc:
        step.update(ok=False, detail=f"HTTP 200 但响应体解析失败: {exc}")
    return step


# ---------------------------------------------------------------------------
# OpenAI compatibility matrix（显式 --matrix 才执行）
# ---------------------------------------------------------------------------
MATRIX_CELLS = (
    ("chat_completions", "Chat Completions"),
    ("responses_api", "Responses API"),
    ("streaming_sse", "Streaming SSE"),
    ("tool_calling", "Tool Calling"),
    ("json_schema", "JSON Schema"),
)
MATRIX_MAX_BODY = 2 * 1024 * 1024
MATRIX_TOOL_NAME = "llm_probe_lookup"
MATRIX_SCHEMA = {
    "type": "object",
    "properties": {"status": {"type": "string", "enum": ["ok"]}},
    "required": ["status"],
    "additionalProperties": False,
}
MATRIX_NETWORK_DETAILS = {
    "dns": "DNS 解析失败（域名不存在或无网络）",
    "timeout": "请求超时",
    "refused": "连接被拒绝（端口没开）",
    "tls": "TLS 失败",
    "net": "网络错误",
}


def _matrix_content_text(value):
    """从 OpenAI 常见的字符串/分段 content 中提取文本。"""
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        pieces = []
        for item in value:
            if isinstance(item, str):
                pieces.append(item)
            elif isinstance(item, dict):
                text = item.get("text")
                if isinstance(text, str):
                    pieces.append(text)
        return "".join(pieces)
    return ""


def parse_chat_completion(data):
    """校验一个最小、非流式 Chat Completions 响应。"""
    if not isinstance(data, dict) or not isinstance(data.get("choices"), list) or not data["choices"]:
        raise ValueError("缺少非空 choices")
    choice = data["choices"][0]
    message = choice.get("message") if isinstance(choice, dict) else None
    if not isinstance(message, dict) or "content" not in message:
        raise ValueError("缺少 message.content")
    content = _matrix_content_text(message.get("content"))
    if not isinstance(content, str) or not content.strip():
        raise ValueError("message.content 不是非空文本")
    return content, choice.get("finish_reason") or ""


def parse_responses_object(data):
    """校验 Responses API 的最小完成响应，允许 reasoning item 先于文本。"""
    if not isinstance(data, dict) or data.get("object") != "response":
        raise ValueError("object 不是 response")
    if data.get("status") != "completed":
        raise ValueError("status 不是 completed")
    top_level = _matrix_content_text(data.get("output_text"))
    if top_level.strip():
        return top_level
    for item in data.get("output") or []:
        if not isinstance(item, dict):
            continue
        for block in item.get("content") or []:
            if isinstance(block, dict) and block.get("type") == "output_text":
                text = _matrix_content_text(block.get("text"))
                if text.strip():
                    return text
    raise ValueError("没有 output_text")


def parse_sse_events(body):
    """解析 SSE，返回事件、聚合文本，并要求标准 [DONE] 终止帧。

    支持 CRLF、注释/keepalive 和多行 data；不把未解析的原始 SSE 放进报告。
    """
    if isinstance(body, bytes):
        text = body.decode("utf-8", "replace")
    else:
        text = str(body)
    events = []
    data_lines = []
    terminal = False

    def flush():
        nonlocal terminal
        if not data_lines:
            return
        payload = "\n".join(data_lines)
        data_lines[:] = []
        if payload.strip() == "[DONE]":
            terminal = True
            return
        try:
            event = json.loads(payload)
        except (TypeError, ValueError) as exc:
            raise ValueError("SSE data 不是合法 JSON: %s" % exc)
        if not isinstance(event, dict):
            raise ValueError("SSE data 不是 JSON object")
        events.append(event)

    for line in text.splitlines():
        if not line:
            flush()
            continue
        if line.startswith(":"):
            continue
        if line.startswith("data:"):
            data_lines.append(line[5:].lstrip(" "))
    flush()

    if not terminal:
        raise ValueError("SSE 缺少 [DONE]")
    if not events:
        raise ValueError("SSE 没有有效事件")
    chunks = []
    for event in events:
        if event.get("object") != "chat.completion.chunk":
            raise ValueError("SSE 事件不是 chat.completion.chunk")
        if not isinstance(event.get("choices"), list):
            raise ValueError("SSE chunk 缺少 choices")
        choices = event["choices"]
        if choices and isinstance(choices[0], dict):
            delta = choices[0].get("delta") or {}
            if isinstance(delta, dict) and isinstance(delta.get("content"), str):
                chunks.append(delta["content"])
    if not "".join(chunks).strip():
        raise ValueError("SSE 没有文本 delta")
    return events, "".join(chunks)


def parse_tool_call(data):
    """校验现代 tool_calls（不把旧 function_call 误判为支持）。"""
    if not isinstance(data, dict) or not isinstance(data.get("choices"), list) or not data["choices"]:
        raise ValueError("缺少非空 choices")
    choice = data["choices"][0]
    if not isinstance(choice, dict) or choice.get("finish_reason") != "tool_calls":
        raise ValueError("finish_reason 不是 tool_calls")
    message = choice.get("message") or {}
    calls = message.get("tool_calls") if isinstance(message, dict) else None
    if not isinstance(calls, list) or not calls:
        raise ValueError("缺少 tool_calls")
    call = calls[0]
    function = call.get("function") if isinstance(call, dict) else None
    if not isinstance(call, dict) or not call.get("id") or not isinstance(function, dict):
        raise ValueError("tool_call 缺少 id/function")
    if function.get("name") != MATRIX_TOOL_NAME:
        raise ValueError("tool name 不匹配")
    arguments = function.get("arguments")
    if not isinstance(arguments, str):
        raise ValueError("tool arguments 不是字符串")
    try:
        parsed = json.loads(arguments)
    except (TypeError, ValueError) as exc:
        raise ValueError("tool arguments 不是合法 JSON: %s" % exc)
    if parsed != {"city": "Paris"} or list(parsed) != ["city"]:
        raise ValueError("tool arguments 不符合固定 schema")
    return call


def parse_schema_output(data):
    """校验 response_format=json_schema 返回的严格小对象。"""
    if not isinstance(data, dict) or not isinstance(data.get("choices"), list) or not data["choices"]:
        raise ValueError("缺少非空 choices")
    choice = data["choices"][0]
    if not isinstance(choice, dict):
        raise ValueError("choice 不是 object")
    message = choice.get("message") or {}
    raw = _matrix_content_text(message.get("content"))
    if not raw.strip():
        raise ValueError("schema 响应没有 content")
    try:
        value = json.loads(raw)
    except (TypeError, ValueError) as exc:
        raise ValueError("schema content 不是合法 JSON: %s" % exc)
    if value != {"status": "ok"}:
        raise ValueError("schema content 不符合固定 schema")
    return value


def _matrix_headers(key, stream=False):
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    if stream:
        headers["Accept"] = "text/event-stream"
    if key:
        headers["Authorization"] = "Bearer %s" % key
    return headers


def _matrix_payload(feature, model, max_tokens):
    """构造五个可重复、无副作用的兼容性请求。"""
    if feature == "chat_completions":
        return {
            "model": model, "messages": [{"role": "user", "content": "Reply with exactly OK."}],
            "max_tokens": max_tokens, "temperature": 0,
        }
    if feature == "responses_api":
        return {"model": model, "input": "Reply with exactly OK.",
                "max_output_tokens": max_tokens, "temperature": 0}
    if feature == "streaming_sse":
        return {
            "model": model, "messages": [{"role": "user", "content": "Reply with exactly OK."}],
            "max_tokens": max_tokens, "temperature": 0, "stream": True,
        }
    if feature == "tool_calling":
        return {
            "model": model,
            "messages": [{"role": "user", "content": "Look up Paris using the tool."}],
            "max_tokens": max_tokens, "temperature": 0,
            "tools": [{"type": "function", "function": {
                "name": MATRIX_TOOL_NAME,
                "description": "Return the city for a fixed compatibility probe.",
                "parameters": {
                    "type": "object", "properties": {"city": {"type": "string"}},
                    "required": ["city"], "additionalProperties": False,
                },
            }}],
            "tool_choice": {"type": "function", "function": {"name": MATRIX_TOOL_NAME}},
        }
    if feature == "json_schema":
        return {
            "model": model,
            "messages": [{"role": "user", "content": 'Return exactly {"status":"ok"}.'}],
            "max_tokens": max_tokens, "temperature": 0,
            "response_format": {
                "type": "json_schema",
                "json_schema": {
                    "name": "llm_probe_result", "strict": True, "schema": MATRIX_SCHEMA,
                },
            },
        }
    raise ValueError("未知 matrix feature: %s" % feature)


def _matrix_http_failure(result):
    """把非 200/传输失败归入现有 2/3/4 语义。"""
    error = result.get("error")
    if error:
        kind = error.get("kind")
        if kind in ("dns", "timeout", "refused", "tls", "net"):
            return kind, result["ms"], MATRIX_NETWORK_DETAILS.get(kind, "网络错误")
        if kind == "body_too_large":
            status = result.get("status", 0)
            return "malformed", result["ms"], "HTTP %d 但响应体超过大小上限" % status
        return "malformed", result["ms"], "请求失败: %s" % error.get("message", "")
    status = result.get("status", 0)
    if status in (401, 403):
        return "auth", result["ms"], "HTTP %d：认证失败" % status
    if 300 <= status < 400:
        return "redirect", result["ms"], "HTTP %d：拒绝重定向" % status
    if status in (404, 405):
        return "unsupported", result["ms"], "HTTP %d：该能力未实现或路径不支持" % status
    if status == 400:
        return "badrequest", result["ms"], "HTTP 400：该能力不支持或请求被拒绝"
    if status == 429:
        return "ratelimit", result["ms"], "HTTP 429：限流 / 额度耗尽"
    if status >= 500:
        return "server", result["ms"], "HTTP %d：服务端错误" % status
    return "client", result["ms"], "HTTP %d：异常响应" % status


def _matrix_run_cell(feature, base_url, key, model, max_tokens, timeout):
    stream = feature == "streaming_sse"
    url = base_url.rstrip("/") + ("/responses" if feature == "responses_api" else "/chat/completions")
    result = http_call(
        url, "POST", _matrix_headers(key, stream=stream), _matrix_payload(feature, model, max_tokens),
        timeout=timeout, max_body_bytes=MATRIX_MAX_BODY,
    )
    name = dict(MATRIX_CELLS)[feature]
    if result.get("error") or result.get("status") != 200:
        kind, elapsed, detail = _matrix_http_failure(result)
        supported = False if kind in ("unsupported", "badrequest", "malformed", "client", "server", "ratelimit") else None
        return {"id": feature, "name": name, "ok": False, "skipped": False,
                "supported": supported, "status": result.get("status", 0), "kind": kind,
                "ms": elapsed, "detail": detail}
    try:
        content_type = result.get("headers", {}).get("content-type", "").split(";", 1)[0].strip().lower()
        if stream and content_type != "text/event-stream":
            raise ValueError("Content-Type 不是 text/event-stream")
        if feature == "chat_completions":
            parse_chat_completion(json.loads(result["body"].decode("utf-8")))
            detail = "HTTP 200，chat.completions 返回可解析回复"
        elif feature == "responses_api":
            parse_responses_object(json.loads(result["body"].decode("utf-8")))
            detail = "HTTP 200，Responses API 返回可解析输出"
        elif feature == "streaming_sse":
            parse_sse_events(result["body"])
            detail = "HTTP 200，SSE 事件与 [DONE] 完整"
        elif feature == "tool_calling":
            parse_tool_call(json.loads(result["body"].decode("utf-8")))
            detail = "HTTP 200，tool_calls、arguments 与 finish_reason 有效"
        else:
            parse_schema_output(json.loads(result["body"].decode("utf-8")))
            detail = "HTTP 200，JSON Schema 输出符合约定"
    except (UnicodeDecodeError, ValueError, TypeError, KeyError, AttributeError, IndexError) as exc:
        return {"id": feature, "name": name, "ok": False, "skipped": False,
                "supported": False, "status": result.get("status", 0), "kind": "malformed",
                "ms": result["ms"], "detail": "HTTP 200 但响应格式不符合 OpenAI 兼容约定"}
    return {"id": feature, "name": name, "ok": True, "skipped": False, "supported": True,
            "status": 200, "kind": None, "ms": result["ms"], "detail": detail}


def _matrix_skip(feature, detail="前置能力失败，已跳过（--all 可强制执行）", kind=None):
    name = dict(MATRIX_CELLS)[feature]
    return {"id": feature, "name": name, "ok": False, "skipped": True,
            "supported": None, "status": 0, "kind": kind, "ms": 0.0, "detail": detail}


def matrix_verdict(steps, allow_unsupported=False):
    """汇总兼容矩阵，保持 2/3/4 的全局退出码优先级。"""
    passed = sum(1 for step in steps if step.get("ok"))
    skipped = sum(1 for step in steps if step.get("skipped"))
    failed = len(steps) - passed - skipped
    failures = [step for step in steps if not step.get("ok") and not step.get("skipped")]
    chat_step = next((step for step in steps if step.get("id") == "chat_completions"), None)
    chat_ok = bool(chat_step and chat_step.get("ok"))
    network_kinds = ("dns", "timeout", "refused", "tls", "net")
    network_steps = [step for step in steps if step.get("kind") in network_kinds]
    if network_steps:
        first = network_steps[0]
        return 2, "网络不可达：%s" % first["detail"], {"passed": passed, "failed": failed,
                                                    "skipped": skipped, "total": len(steps)}
    if any(step.get("kind") == "auth" for step in failures):
        first = next(step for step in failures if step.get("kind") == "auth")
        return 3, "认证失败：%s" % first["detail"], {"passed": passed, "failed": failed,
                                                    "skipped": skipped, "total": len(steps)}
    if failures and allow_unsupported and chat_ok and all(
            step.get("kind") == "unsupported" for step in failures):
        ids = "、".join(step["id"] for step in failures)
        return 0, "兼容能力通过（未实现：%s）" % ids, {"passed": passed, "failed": failed,
                                                     "skipped": skipped, "total": len(steps)}
    if failures:
        ids = "、".join(step["id"] for step in failures)
        if not ids:
            ids = "chat_completions"
        return 4, "兼容能力不通过：%s" % ids, {"passed": passed, "failed": failed,
                                             "skipped": skipped, "total": len(steps)}
    if not chat_ok:
        return 4, "兼容能力不通过：chat_completions", {"passed": passed, "failed": failed,
                                                       "skipped": skipped, "total": len(steps)}
    return 0, "兼容能力通过：%d 项" % len(steps), {"passed": passed, "failed": failed,
                                                 "skipped": skipped, "total": len(steps)}


def run_compatibility_matrix(base_url, key, model, max_tokens, timeout, force_all=False,
                             allow_unsupported=False):
    """运行五个显式兼容性单元；默认在传输/认证故障后跳过后续请求。"""
    network = step_network(base_url, timeout)
    if not network.get("ok"):
        network_kind = network.get("kind") or "net"
        steps = [_matrix_skip(feature, network["detail"], kind=network_kind)
                 for feature, _ in MATRIX_CELLS]
        code, verdict, summary = matrix_verdict(steps)
        return steps, code, verdict, summary
    steps = []
    gated = False
    for feature, _ in MATRIX_CELLS:
        if gated and not force_all:
            steps.append(_matrix_skip(feature))
            continue
        row = _matrix_run_cell(feature, base_url, key, model, max_tokens, timeout)
        steps.append(row)
        if (not row["ok"] and not force_all and
                row.get("kind") in ("dns", "timeout", "refused", "tls", "net", "auth", "ratelimit")):
            gated = True
    code, verdict, summary = matrix_verdict(steps, allow_unsupported=allow_unsupported)
    return steps, code, verdict, summary


def step_sdk(base_url, key, model, prompt, timeout):
    try:
        import openai  # noqa
    except ImportError:
        return {"name": "L4 SDK", "ok": False, "kind": "nosdk", "fatal": False,
                "detail": "未安装 openai SDK（pip install -U openai）"}
    version = getattr(openai, "__version__", "未知")
    start = time.monotonic()
    try:
        if hasattr(openai, "OpenAI"):  # openai >= 1.0
            client = openai.OpenAI(base_url=base_url, api_key=key, timeout=timeout)
            resp = client.chat.completions.create(
                model=model, messages=[{"role": "user", "content": prompt}],
                max_tokens=32,
            )
            content = resp.choices[0].message.content or ""
            style = "1.x 新客户端"
        else:  # openai 0.28 老 API
            openai.api_base = base_url
            openai.api_key = key
            resp = openai.ChatCompletion.create(
                model=model, messages=[{"role": "user", "content": prompt}],
                max_tokens=32, request_timeout=timeout,
            )
            content = resp["choices"][0]["message"]["content"] or ""
            style = "0.x 老 API"
        ms = round((time.monotonic() - start) * 1000, 1)
        return {"name": "L4 SDK", "ok": True, "ms": ms,
                "detail": f"openai {version}（{style}）调用成功 ({ms}ms)",
                "content": content.strip()}
    except Exception as exc:
        ms = round((time.monotonic() - start) * 1000, 1)
        message = str(exc)
        for prefix in ("Error while finding module specification.",
                       "Invalid URL", "HTTPSConnectionPool"):
            if message.startswith(prefix):
                message = message.split("\n")[0][:160]
                break
        return {"name": "L4 SDK", "ok": False, "kind": "sdk", "ms": ms,
                "detail": f"openai {version} 调用失败: {message.splitlines()[0][:160]}",
                "fatal": True}


# ---------------------------------------------------------------------------
# 报告
# ---------------------------------------------------------------------------
def verdict_of(steps):
    """按层级给出唯一结论 + 退出码。"""
    by_name = {s["name"]: s for s in steps}
    net = by_name.get("L1 网络")
    auth = by_name.get("L2 认证")
    infer = by_name.get("L3 推理")
    sdk = by_name.get("L4 SDK")

    if net and not net["ok"]:
        return 2, f"网络不可达：{net['detail']}"
    if auth and not auth["ok"] and auth.get("fatal", True):
        if auth.get("kind") == "auth":
            return 3, f"认证失败：API Key 无效或已过期（{auth['detail']}）"
        if auth.get("kind") == "ratelimit":
            return 3, f"认证被拒：限流或额度耗尽（{auth['detail']}）"
        if auth.get("kind") in ("timeout", "refused", "dns", "tls", "net"):
            return 2, f"网络不可达：{auth['detail']}"
        return 3, f"认证环节异常：{auth['detail']}"
    if infer is not None and not infer["ok"]:
        kind = infer.get("kind")
        if kind == "auth":
            return 3, f"认证失败：{infer['detail']}"
        if kind == "notfound":
            return 4, f"路径不对：{infer['detail']}（检查 base_url 是否含 /v1）"
        if kind == "badrequest":
            return 4, f"请求参数不被接受：{infer['detail']}（多半是模型名不对）"
        if kind == "ratelimit":
            return 4, f"限流 / 额度耗尽：{infer['detail']}"
        if kind in ("timeout", "refused", "dns", "tls", "net"):
            return 2, f"网络不可达：{infer['detail']}"
        return 4, f"推理失败：{infer['detail']}"
    if sdk is not None and not sdk["ok"] and sdk.get("fatal"):
        return 5, f"SDK 调用失败：{sdk['detail']}"
    parts = []
    if infer and infer["ok"]:
        parts.append("推理正常")
    elif infer is None:
        parts.append("推理未测")
    if auth and auth["ok"]:
        parts.append("认证通过")
    if auth and not auth["ok"] and not auth.get("fatal", True):
        parts.append(f"认证跳过（{auth['detail']}）")
    if sdk is not None:
        parts.append("SDK 正常" if sdk["ok"] else f"SDK {sdk['detail']}")
    return 0, "；".join(parts)


def print_report(result, as_json=False):
    if as_json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return
    print("=" * 60)
    print(f"端点   : {result['base_url']}")
    print(f"模型   : {result['model']}")
    print(f"密钥   : {result['key_masked']}")
    print("-" * 60)
    total = len(result["steps"])
    for index, step in enumerate(result["steps"], 1):
        mark = "OK  " if step["ok"] else ("SKIP" if step.get("skipped") else "FAIL")
        tail = f" [{index}/{total}]"
        print(f"[{mark}] {step['name']}{tail}  {step['detail']}")
        if step.get("content"):
            snippet = step["content"].replace("\n", " ")[:200]
            print(f"          回复: {snippet}")
    if result.get("mode") == "compatibility":
        summary = result.get("summary", {})
        print("-" * 60)
        print("矩阵   : %d 通过 / %d 失败 / %d 跳过 / %d 总计" % (
            summary.get("passed", 0), summary.get("failed", 0),
            summary.get("skipped", 0), summary.get("total", total)))
    print("-" * 60)
    mark = "✅" if result["exit_code"] == 0 else "❌"
    print(f"结论 {mark} {result['verdict']}")
    print(f"退出码 {result['exit_code']}")
    print("=" * 60)


# ---------------------------------------------------------------------------
# 子命令
# ---------------------------------------------------------------------------
def cmd_probe(args):
    if getattr(args, "allow_unsupported", False) and not getattr(args, "matrix", False):
        print("参数错误：--allow-unsupported 只能与 --matrix 同时使用", file=sys.stderr)
        return 1
    if getattr(args, "matrix", False) and (args.only or args.sdk):
        print("参数错误：--matrix 不能与 --only 或 --sdk 同时使用", file=sys.stderr)
        return 1
    config_path = os.path.expanduser(args.config)
    cfg = {}
    if os.path.exists(config_path):
        cfg = read_config(config_path)
    elif args.config != DEFAULT_CONFIG:
        print(f"配置文件不存在: {config_path}", file=sys.stderr)
        return 1

    # 优先级：命令行 > 环境变量 > 配置文件（与 llm_probe.sh 一致）
    base_url = args.base_url or os.environ.get("LLM_BASE_URL") or cfg.get("LLM_BASE_URL")
    model = args.model or os.environ.get("LLM_MODEL") or cfg.get("LLM_MODEL")
    if not base_url:
        print("缺少 base_url：用 --base-url 或在配置里填 LLM_BASE_URL", file=sys.stderr)
        return 1
    if not model:
        print("缺少模型名：用 --model 或在配置里填 LLM_MODEL", file=sys.stderr)
        return 1
    if not base_url.startswith(("http://", "https://")):
        print(f"base_url 非法（需要 http(s)://host[/v1]）: {base_url}", file=sys.stderr)
        return 1

    prompt = args.prompt or os.environ.get("LLM_PROMPT") or cfg.get("LLM_PROMPT") or "你好"
    # 注意不能用 `args.x or ...`：显式传 0 会被当成"没传"而绕过下面的校验
    # （--timeout 0 / --max-tokens 0 必须报"必须大于 0"，而不是悄悄用默认值）
    timeout_raw = (args.timeout if args.timeout is not None
                   else os.environ.get("LLM_TIMEOUT") or cfg.get("LLM_TIMEOUT") or 30)
    tokens_raw = (args.max_tokens if args.max_tokens is not None
                  else os.environ.get("LLM_MAX_TOKENS") or cfg.get("LLM_MAX_TOKENS") or 64)
    try:
        timeout = float(timeout_raw)
        max_tokens = int(tokens_raw)
    except (TypeError, ValueError):
        print("配置错误：timeout 必须是数字（如 30、2.5），max-tokens 必须是整数",
              file=sys.stderr)
        return 1
    if timeout <= 0 or max_tokens <= 0:
        print("配置错误：timeout 与 max-tokens 必须大于 0", file=sys.stderr)
        return 1

    if args.only == "net":
        # 不用密钥，但环境里那份也不能留给子进程（与 sh 一致）
        scrub_env("LLM_API_KEY")
        key, key_source = None, "未读取（--only net 不需要密钥）"
    else:
        key, key_source = resolve_key(args, cfg)

    # L1 是裸 socket，天然不走代理；--direct 让 L2/L3 也绕开代理，保持口径一致。
    # HTTP opener 同时拒绝跨 origin 重定向，避免 Authorization 被转发到第三方。
    install_http_opener(direct=args.direct)

    if getattr(args, "matrix", False):
        steps, code, verdict, summary = run_compatibility_matrix(
            base_url, key, model, max_tokens, timeout, force_all=args.all,
            allow_unsupported=getattr(args, "allow_unsupported", False),
        )
        result = {
            "version": VERSION,
            "mode": "compatibility",
            "base_url": base_url,
            "model": model,
            "key_masked": mask_secret(key),
            "key_source": key_source,
            "config": config_path if os.path.exists(config_path) else None,
            "steps": steps,
            "summary": summary,
            "verdict": verdict,
            "exit_code": code,
        }
        print_report(result, args.json)
        return code

    # --only 决定跑哪几层：net=L1；auth=L1+L2；infer=L1+L3；sdk=L1+L4；缺省全跑
    only = args.only
    steps = [step_network(base_url, timeout)]

    auth_step = None
    if only in (None, "auth"):
        auth_step = step_auth(base_url, key, timeout)
        steps.append(auth_step)

    # L2 已经判定 key 有问题时，L3 没必要再烧一次请求，除非 --all 强制
    blocked = (auth_step is not None and not auth_step["ok"]
               and auth_step.get("kind") in ("auth", "ratelimit") and not args.all)

    if only in (None, "infer"):
        if blocked:
            steps.append({"name": "L3 推理", "ok": False, "skipped": True,
                          "detail": "L2 认证未通过，已跳过（--all 可强制执行）"})
        else:
            step = step_infer(base_url, key, model, prompt, max_tokens, timeout)
            # 与 sh 端 JSON 对齐：L3 恒带 skipped 字段（真跑过 = false）
            step.setdefault("skipped", False)
            steps.append(step)

    if only in (None, "sdk") and (args.sdk or only == "sdk"):
        steps.append(step_sdk(base_url, key, model, prompt, timeout))

    code, verdict = verdict_of(steps)
    result = {
        "version": VERSION,
        "base_url": base_url,
        "model": model,
        "key_masked": mask_secret(key),
        "key_source": key_source,
        "config": config_path if os.path.exists(config_path) else None,
        "steps": steps,
        "verdict": verdict,
        "exit_code": code,
    }
    print_report(result, args.json)
    return code


def resolve_key(args, cfg):
    """密钥优先级：--key > LLM_API_KEY 环境变量 > 解密 LLM_API_KEY_ENC > LLM_API_KEY 明文。"""
    if getattr(args, "key", None):
        warn_secret_arg("--key")
        # --key 已经给定，环境里那份就多余了：同样摘掉，别让子进程继承
        scrub_env("LLM_API_KEY")
        return args.key, "--key 参数"
    if os.environ.get("LLM_API_KEY"):
        value = os.environ["LLM_API_KEY"]
        scrub_env("LLM_API_KEY")   # 同口令：读到就摘，别让它跟着子进程走
        return value, "环境变量 LLM_API_KEY"
    token = cfg.get("LLM_API_KEY_ENC") or os.environ.get("LLM_API_KEY_ENC")
    if token:
        passphrase = read_passphrase(args, cfg)
        if not passphrase:
            raise SystemExit(
                "配置里是加密密钥，但拿不到解密口令。按推荐顺序任选其一：\n"
                "  1) LLM_PASSPHRASE_FILE 指向口令文件（chmod 600，非交互场景首选）\n"
                "  2) 在终端交互输入（最安全）\n"
                "  3) 环境变量 LLM_PASSPHRASE（权宜之计：环境变量会被子进程继承，\n"
                "     读到后本脚本会立即摘掉；详见 README「口令从哪来」权衡表）")
        try:
            return decrypt_secret(token, passphrase), "配置文件（已解密）"
        except ValueError as exc:
            raise SystemExit(f"解密失败: {exc}")
    plain = cfg.get("LLM_API_KEY")
    if plain:
        return plain, "配置文件明文 LLM_API_KEY"
    return None, "未提供（将只做匿名探测）"


def cmd_init(args):
    return init_config(os.path.expanduser(args.config), force=getattr(args, "force", False))


def cmd_setkey(args):
    config_path = os.path.expanduser(args.config)
    if not os.path.exists(config_path):
        if init_config(config_path):
            return 1
    cfg = read_config(config_path)
    if getattr(args, "key", None):
        warn_secret_arg("--key")
        key = args.key
    else:
        key = os.environ.get("LLM_API_KEY")
    if key:
        # 选完就摘：来源是 --key 还是环境变量，都不留给子进程
        scrub_env("LLM_API_KEY")
    if not key:
        if sys.stdin.isatty():
            import getpass
            key = getpass.getpass("API Key: ").strip()
        else:
            # 非交互：优先从 stdin 读。管道内容不进 argv、不进 shell 历史。
            data = sys.stdin.read().strip()
            key = data.splitlines()[0].strip() if data else ""
            if not key:
                print(
                    "拿不到密钥。非交互环境建议从管道读：\n"
                    "  printf '%s' \"$KEY\" | python3 llm_probe.py setkey\n"
                    "  （或用 LLM_API_KEY 环境变量；--key 会留在 shell 历史和 ps 进程列表里）",
                    file=sys.stderr,
                )
                return 1
    if not key:
        print("密钥为空", file=sys.stderr)
        return 1
    passphrase = read_passphrase(args, cfg, confirm=True)
    if not passphrase:
        print("需要解密口令（以后读取密钥时要用同一个口令）", file=sys.stderr)
        return 1
    try:
        token = encrypt_secret(key, passphrase)
    except (ValueError, subprocess.SubprocessError) as exc:
        print(f"加密失败: {exc}", file=sys.stderr)
        return 1
    update_env_file(config_path, {"LLM_API_KEY_ENC": token, "LLM_API_KEY": ""})
    print(f"已加密写入: {config_path}")
    print(f"密钥       : {mask_secret(key)}")
    print(f"密文       : {token[:38]}...（共 {len(token)} 字符）")
    print("注意：口令不会保存在配置里，别忘了它——丢了就只能重新 setkey。")
    return 0


def cmd_showkey(args):
    cfg = read_config(os.path.expanduser(args.config))
    token = cfg.get("LLM_API_KEY_ENC")
    if not token:
        plain = cfg.get("LLM_API_KEY")
        if plain:
            print(f"明文密钥: {mask_secret(plain)}")
            return 0
        print("配置里没有密钥", file=sys.stderr)
        return 1
    passphrase = read_passphrase(args, cfg)
    if not passphrase:
        print("拿不到解密口令", file=sys.stderr)
        return 1
    try:
        key = decrypt_secret(token, passphrase)
    except ValueError as exc:
        print(f"解密失败: {exc}", file=sys.stderr)
        return 1
    print(key if args.plain else mask_secret(key))
    return 0


def cmd_env(args):
    cfg = read_config(os.path.expanduser(args.config))
    try:
        key, source = resolve_key(args, cfg)
    except SystemExit as exc:
        print(exc, file=sys.stderr)
        return 1
    print(f"配置文件 : {os.path.expanduser(args.config)}")
    for name in ("LLM_BASE_URL", "LLM_MODEL", "LLM_TIMEOUT",
                 "LLM_PROMPT", "LLM_MAX_TOKENS", "LLM_PASSPHRASE_FILE"):
        value = cfg.get(name, "")
        print(f"{name:<22}= {value or '(未设置)'}")
    print(f"{'LLM_API_KEY':<22}= {mask_secret(key)}  [{source}]")
    print(f"{'LLM_API_KEY_ENC':<22}= {cfg.get('LLM_API_KEY_ENC', '')[:32] or '(未设置)'}")
    return 0


class _ArgumentParser(argparse.ArgumentParser):
    """参数/用法错误一律退出 1。

    argparse 默认退出 2，而本工具的 2 = 网络不通；CI 里按退出码分诊的话，
    一个拼错的参数会被误判成网络故障。
    """

    def error(self, message):
        self.print_usage(sys.stderr)
        print(f"参数错误: {message}", file=sys.stderr)
        raise SystemExit(1)


def build_parser():
    # 公共选项放在 parent 里，主命令和所有子命令都能用，且带 SUPPRESS，
    # 这样 `llm_probe.py -c x probe` 和 `llm_probe.py probe -c x` 都不互相覆盖。
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("-c", "--config", default=argparse.SUPPRESS, metavar="FILE",
                        help=f"配置文件 (默认: {DEFAULT_CONFIG})")

    # 子命令 parser 会自动沿用这个类（add_subparsers 默认 parser_class=type(self)）
    parser = _ArgumentParser(
        prog="llm_probe.py",
        parents=[common],
        description="OpenAI 兼容 LLM 端点连通性探测（网络/认证/推理/SDK 分层检查，密钥加密存储）。",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""示例:
  python3 llm_probe.py init                  生成配置文件
  python3 llm_probe.py setkey                交互写入加密密钥
  python3 llm_probe.py probe                 分层探测（不写 probe 也行）
  python3 llm_probe.py probe --sdk           追加真实 openai SDK 调用
  python3 llm_probe.py probe --matrix        五项 OpenAI 兼容能力矩阵
  python3 llm_probe.py probe --matrix --json  机器可读的兼容矩阵
  python3 llm_probe.py --base-url https://api.openai.com/v1 --model gpt-4o-mini

退出码:
  0 全部通过  1 用法/配置错误  2 网络不通  3 认证失败  4 推理失败  5 SDK 失败
""",
    )
    parser.add_argument("-v", "--version", action="version", version=f"%(prog)s {VERSION}")
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")

    probe = sub.add_parser("probe", parents=[common], help="分层探测（默认动作）")
    probe.add_argument("--base-url", metavar="URL")
    probe.add_argument("--model", metavar="NAME")
    probe.add_argument("--prompt", metavar="TEXT")
    probe.add_argument("--timeout", type=float, metavar="SEC")
    probe.add_argument("--max-tokens", type=int, metavar="N")
    probe.add_argument("--key", metavar="KEY",
                       help="临时指定密钥（不读配置；会留在 shell 历史和 ps 进程列表里，仅测试用）")
    probe.add_argument("--passphrase", metavar="PWD",
                       help="解密口令（同上；推荐 LLM_PASSPHRASE_FILE 口令文件或交互输入）")
    probe.add_argument("--only", choices=("net", "auth", "infer", "sdk"),
                       help="只跑某一层: net=L1 / auth=L1+L2 / infer=L1+L3 / sdk=L1+L4")
    probe.add_argument("--all", action="store_true", help="认证失败也继续测推理")
    probe.add_argument("--sdk", action="store_true", help="追加 openai SDK 真实调用")
    probe.add_argument("--matrix", action="store_true",
                       help="运行五项 OpenAI 兼容能力矩阵（chat/responses/stream/tools/schema）")
    probe.add_argument("--allow-unsupported", action="store_true",
                       help="chat 已通过时，矩阵中仅 404/405 未实现能力仍返回 0")
    probe.add_argument("--direct", action="store_true",
                       help="不走系统代理（绕过 http_proxy/https_proxy）")
    probe.add_argument("--json", action="store_true", help="JSON 输出")

    init = sub.add_parser("init", parents=[common], help="生成配置文件")
    init.add_argument("--force", action="store_true", help="覆盖已存在的配置")

    setkey = sub.add_parser("setkey", parents=[common], help="加密写入 API Key")
    setkey.add_argument("--key", metavar="KEY",
                        help="密钥直接给（会留在 shell 历史/ps；推荐交互输入或 stdin 管道）")
    setkey.add_argument("--passphrase", metavar="PWD",
                        help="解密口令直接给（同上；推荐口令文件或交互输入）")

    showkey = sub.add_parser("showkey", parents=[common], help="解密显示 API Key")
    showkey.add_argument("--plain", action="store_true", help="显示完整明文")
    showkey.add_argument("--passphrase", metavar="PWD",
                         help="解密口令直接给（会留在 shell 历史/ps；推荐口令文件或交互输入）")

    env = sub.add_parser("env", parents=[common], help="打印生效配置")
    env.add_argument("--key", metavar="KEY",
                     help="临时指定密钥（会留在 shell 历史/ps，仅测试用）")
    env.add_argument("--passphrase", metavar="PWD",
                     help="解密口令直接给（推荐口令文件或交互输入）")
    return parser


COMMANDS = ("probe", "init", "setkey", "showkey", "env")
VALUE_OPTIONS = ("-c", "--config", "--key", "--passphrase", "--base-url", "--model",
                 "--prompt", "--timeout", "--max-tokens", "--only")


def _scan_argv(argv):
    """返回 "cmd"(已显式写子命令) / "global"(只碰到 -h/-v 这类全局开关) / "none"。"""
    index = 0
    while index < len(argv):
        token = argv[index]
        if token in COMMANDS:
            return "cmd"
        if token in ("-h", "--help", "-v", "--version"):
            return "global"
        if token == "--":
            return "none"
        if token in VALUE_OPTIONS:   # 吃掉下一个 token，避免把 --model showkey 当子命令
            index += 2
            continue
        index += 1
    return "none"


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if _scan_argv(argv) == "none":
        # 没写子命令也没碰全局开关 → 当作 probe（probe 的选项顶层不认识）
        argv = ["probe"] + argv

    parser = build_parser()
    args = parser.parse_args(argv)
    if not hasattr(args, "config"):
        args.config = DEFAULT_CONFIG

    handlers = {"probe": cmd_probe, "init": cmd_init, "setkey": cmd_setkey,
                "showkey": cmd_showkey, "env": cmd_env}
    command = handlers[args.command or "probe"]
    try:
        return command(args)
    except KeyboardInterrupt:
        print("\n已中断", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
