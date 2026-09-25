#!/usr/bin/env python3
"""最小可运行 demo：用 openai SDK 打一个 OpenAI 兼容端点。

只做一件事——发一条消息，打印回复。
不做分层诊断、不打印耗时、不解析错误码；那些是 llm_probe.py 的活。

用法:
    export LLM_PASSPHRASE='你的口令'        # 密钥加密存着时才需要
    python3 demo_minimal.py

    # 或者完全绕过配置文件
    LLM_API_KEY=sk-xxx LLM_BASE_URL=https://api.openai.com/v1 \
    LLM_MODEL=gpt-4o-mini python3 demo_minimal.py

依赖: openai >= 0.28（新旧两套写法都兼容）
"""

import os
import sys

# 从同目录的 llm_probe 复用"读配置 + 解密"逻辑，避免在 demo 里重复造轮子
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from llm_probe import DEFAULT_CONFIG, decrypt_secret, parse_env_file, scrub_env  # noqa: E402

# 默认走官方端点；任何 OpenAI 兼容端点都可以（用 LLM_BASE_URL 覆盖）。
# 本仓库 README 里的 aiapiv2.pekpik.com 只是第三方中转示例，别默认把密钥
# 发给不认识的服务。
BASE_URL = os.environ.get("LLM_BASE_URL") or "https://api.openai.com/v1"
MODEL = os.environ.get("LLM_MODEL") or "gpt-4o-mini"


def load_api_key():
    """取密钥的三种来源，按优先级：环境变量 > 加密配置 > 明文配置。

    拿到手就把环境变量里的密钥/口令摘掉（scrub_env）：环境变量会被后续每个
    子进程无条件继承，包括 openai SDK 自己拉起来的那些。
    """
    if os.environ.get("LLM_API_KEY"):                     # 1) 环境变量
        value = os.environ["LLM_API_KEY"]
        scrub_env("LLM_API_KEY")
        return value

    cfg = parse_env_file(DEFAULT_CONFIG)
    token = cfg.get("LLM_API_KEY_ENC")                    # 2) 加密配置 enc:v1:...
    if token:
        passphrase = os.environ.get("LLM_PASSPHRASE")
        if not passphrase:
            raise SystemExit(
                "密钥是加密存储的。推荐先配置 LLM_PASSPHRASE_FILE 指向口令文件，"
                "或临时 export LLM_PASSPHRASE=...（读到后会立即从环境里摘掉）")
        os.environ.pop("LLM_PASSPHRASE", None)            # 读到就摘，别广播给子进程
        return decrypt_secret(token, passphrase)

    if cfg.get("LLM_API_KEY"):                            # 3) 明文配置（不推荐）
        return cfg["LLM_API_KEY"]

    raise SystemExit("没有可用的密钥：先跑 python3 llm_probe.py setkey")


def ask(prompt):
    """发一条消息，返回回复文本。自动适配 openai 1.x 与 0.28 两套 API。"""
    key = load_api_key()
    try:
        from openai import OpenAI                         # openai >= 1.0
    except ImportError:
        import openai                                     # openai 0.28 老 API
        openai.api_base = BASE_URL
        openai.api_key = key
        resp = openai.ChatCompletion.create(
            model=MODEL,
            messages=[{"role": "user", "content": prompt}],
            request_timeout=30,
        )
        return resp["choices"][0]["message"]["content"]

    client = OpenAI(base_url=BASE_URL, api_key=key, timeout=30)
    resp = client.chat.completions.create(
        model=MODEL,
        messages=[{"role": "user", "content": prompt}],
    )
    return resp.choices[0].message.content


if __name__ == "__main__":
    print(f"{BASE_URL}  |  {MODEL}")
    try:
        print(ask("你好，请用一句话介绍你自己。"))
    except Exception as exc:                              # 粗分类，退出码与 llm_probe 对齐
        name, text = type(exc).__name__, str(exc).splitlines()[0][:160]
        if "Authentication" in name or "401" in text or "403" in text:
            print(f"认证失败（key 无效）：{text}", file=sys.stderr)
            sys.exit(3)
        if "Connection" in name or "Timeout" in name or "timed out" in text:
            print(f"网络不通：{text}", file=sys.stderr)
            sys.exit(2)
        print(f"调用失败：{text}", file=sys.stderr)
        sys.exit(4)
