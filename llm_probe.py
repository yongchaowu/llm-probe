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

VERSION = "1.0"

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
# 写入密钥:    python3 llm_probe.py setkey        （交互输入，推荐）
#              python3 llm_probe.py setkey --key sk-xxx
# 查看密钥:    python3 llm_probe.py showkey
# 开始探测:    python3 llm_probe.py probe

# OpenAI 兼容端点，通常以 /v1 结尾
LLM_BASE_URL=https://aiapiv2.pekpik.com/v1

# 模型名按服务商自己的命名填
LLM_MODEL=claude-opus-4-7

# 加密后的密钥（enc:v1:... ），由 setkey 写入，不要手填
LLM_API_KEY_ENC=

# 明文密钥：仅用于临时调试。存在时优先级低于 LLM_API_KEY_ENC。
# 用 setkey 写入时会自动清空本行。
LLM_API_KEY=

# 解密口令来源（口令本身永远不写进本文件，否则加密就失去意义了）：
#   1) 环境变量 LLM_PASSPHRASE
#   2) LLM_PASSPHRASE_FILE 指向的口令文件（建议 chmod 600）
#   3) 终端交互输入
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
            value = value.strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
                value = value[1:-1]
            data[key] = value
    return data


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


def _encrypt_openssl(plain, passphrase):
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


def read_passphrase(args, cfg, *, confirm=False, allow_prompt=True):
    """口令来源：--passphrase > LLM_PASSPHRASE 环境变量 > 口令文件 > 交互。"""
    if getattr(args, "passphrase", None):
        return args.passphrase
    if os.environ.get("LLM_PASSPHRASE"):
        return os.environ["LLM_PASSPHRASE"]
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


def http_call(url, method="GET", headers=None, payload=None, timeout=30):
    """发一次 HTTP 请求，永不抛异常，统一返回结构化结果。"""
    body = None
    if payload is not None:
        body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=body, method=method)
    for key, value in (headers or {}).items():
        req.add_header(key, value)
    start = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            return {
                "ok": True, "status": resp.status, "body": raw,
                "ms": round((time.monotonic() - start) * 1000, 1), "error": None,
            }
    except urllib.error.HTTPError as exc:
        try:
            raw = exc.read()
        except Exception:
            raw = b""
        return {
            "ok": False, "status": exc.code, "body": raw,
            "ms": round((time.monotonic() - start) * 1000, 1), "error": None,
        }
    except Exception as exc:
        kind, message = classify_error(exc)
        return {
            "ok": False, "status": 0, "body": b"",
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
    print("-" * 60)
    mark = "✅" if result["exit_code"] == 0 else "❌"
    print(f"结论 {mark} {result['verdict']}")
    print(f"退出码 {result['exit_code']}")
    print("=" * 60)


# ---------------------------------------------------------------------------
# 子命令
# ---------------------------------------------------------------------------
def cmd_probe(args):
    config_path = os.path.expanduser(args.config)
    cfg = {}
    if os.path.exists(config_path):
        cfg = parse_env_file(config_path)
    elif args.config != DEFAULT_CONFIG:
        print(f"配置文件不存在: {config_path}", file=sys.stderr)
        return 1

    base_url = args.base_url or cfg.get("LLM_BASE_URL") or os.environ.get("LLM_BASE_URL")
    model = args.model or cfg.get("LLM_MODEL") or os.environ.get("LLM_MODEL")
    if not base_url:
        print("缺少 base_url：用 --base-url 或在配置里填 LLM_BASE_URL", file=sys.stderr)
        return 1
    if not model:
        print("缺少模型名：用 --model 或在配置里填 LLM_MODEL", file=sys.stderr)
        return 1
    if not base_url.startswith(("http://", "https://")):
        print(f"base_url 非法（需要 http(s)://host[/v1]）: {base_url}", file=sys.stderr)
        return 1

    timeout = float(args.timeout or cfg.get("LLM_TIMEOUT") or 30)
    prompt = args.prompt or cfg.get("LLM_PROMPT") or "你好"
    max_tokens = int(args.max_tokens or cfg.get("LLM_MAX_TOKENS") or 64)

    key, key_source = resolve_key(args, cfg) if args.only != "net" else (
        None, "未读取（--only net 不需要密钥）")

    # L1 是裸 socket，天然不走代理；--direct 让 L2/L3 也绕开代理，保持口径一致
    if args.direct:
        urllib.request.install_opener(
            urllib.request.build_opener(urllib.request.ProxyHandler({})))

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
            steps.append(step_infer(base_url, key, model, prompt, max_tokens, timeout))

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
        return args.key, "--key 参数"
    if os.environ.get("LLM_API_KEY"):
        return os.environ["LLM_API_KEY"], "环境变量 LLM_API_KEY"
    token = cfg.get("LLM_API_KEY_ENC") or os.environ.get("LLM_API_KEY_ENC")
    if token:
        passphrase = read_passphrase(args, cfg)
        if not passphrase:
            raise SystemExit(
                "配置里是加密密钥，但拿不到解密口令。\n"
                "  设置环境变量 LLM_PASSPHRASE，或配置 LLM_PASSPHRASE_FILE，"
                "或在终端交互输入。")
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
    cfg = parse_env_file(config_path)
    key = args.key or os.environ.get("LLM_API_KEY")
    if not key:
        if not sys.stdin.isatty():
            print("非交互环境请用 --key 或 LLM_API_KEY 环境变量传入", file=sys.stderr)
            return 1
        import getpass
        key = getpass.getpass("API Key: ").strip()
    if not key:
        print("密钥为空", file=sys.stderr)
        return 1
    passphrase = read_passphrase(args, cfg, confirm=True)
    if not passphrase:
        print("需要解密口令（以后读取密钥时要用同一个口令）", file=sys.stderr)
        return 1
    token = encrypt_secret(key, passphrase)
    update_env_file(config_path, {"LLM_API_KEY_ENC": token, "LLM_API_KEY": ""})
    print(f"已加密写入: {config_path}")
    print(f"密钥       : {mask_secret(key)}")
    print(f"密文       : {token[:38]}...（共 {len(token)} 字符）")
    print("注意：口令不会保存在配置里，别忘了它——丢了就只能重新 setkey。")
    return 0


def cmd_showkey(args):
    cfg = parse_env_file(os.path.expanduser(args.config))
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
    cfg = parse_env_file(os.path.expanduser(args.config))
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


def build_parser():
    # 公共选项放在 parent 里，主命令和所有子命令都能用，且带 SUPPRESS，
    # 这样 `llm_probe.py -c x probe` 和 `llm_probe.py probe -c x` 都不互相覆盖。
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("-c", "--config", default=argparse.SUPPRESS, metavar="FILE",
                        help=f"配置文件 (默认: {DEFAULT_CONFIG})")

    parser = argparse.ArgumentParser(
        prog="llm_probe.py",
        parents=[common],
        description="OpenAI 兼容 LLM 端点连通性探测（网络/认证/推理/SDK 分层检查，密钥加密存储）。",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""示例:
  python3 llm_probe.py init                  生成配置文件
  python3 llm_probe.py setkey                交互写入加密密钥
  python3 llm_probe.py probe                 分层探测（不写 probe 也行）
  python3 llm_probe.py probe --sdk           追加真实 openai SDK 调用
  python3 llm_probe.py probe --json          机器可读输出
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
    probe.add_argument("--key", metavar="KEY", help="临时指定密钥（不读配置）")
    probe.add_argument("--passphrase", metavar="PWD", help="解密口令（不推荐，会进 shell 历史）")
    probe.add_argument("--only", choices=("net", "auth", "infer", "sdk"),
                       help="只跑某一层: net=L1 / auth=L1+L2 / infer=L1+L3 / sdk=L1+L4")
    probe.add_argument("--all", action="store_true", help="认证失败也继续测推理")
    probe.add_argument("--sdk", action="store_true", help="追加 openai SDK 真实调用")
    probe.add_argument("--direct", action="store_true",
                       help="不走系统代理（绕过 http_proxy/https_proxy）")
    probe.add_argument("--json", action="store_true", help="JSON 输出")

    init = sub.add_parser("init", parents=[common], help="生成配置文件")
    init.add_argument("--force", action="store_true", help="覆盖已存在的配置")

    setkey = sub.add_parser("setkey", parents=[common], help="加密写入 API Key")
    setkey.add_argument("--key", metavar="KEY")
    setkey.add_argument("--passphrase", metavar="PWD")

    showkey = sub.add_parser("showkey", parents=[common], help="解密显示 API Key")
    showkey.add_argument("--plain", action="store_true", help="显示完整明文")
    showkey.add_argument("--passphrase", metavar="PWD")

    env = sub.add_parser("env", parents=[common], help="打印生效配置")
    env.add_argument("--key", metavar="KEY")
    env.add_argument("--passphrase", metavar="PWD")
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
