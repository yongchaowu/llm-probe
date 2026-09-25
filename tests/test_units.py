#!/usr/bin/env python3
"""llm_probe 单元测试：配置解析、加解密、结论映射、密钥卫生、JSON schema。

零第三方依赖，直接跑：
    python3 tests/test_units.py
装了 pytest 的话也能跑（函数按 test_* 命名）：
    python3 -m pytest tests/test_units.py -q
"""
import base64
import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

import llm_probe  # noqa: E402


def _tmp_env(content):
    fd, path = tempfile.mkstemp(suffix=".env")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(content)
    return path


def _raises(fn, *args):
    try:
        fn(*args)
    except ValueError:
        return True
    return False


# ---------------------------------------------------------------------------
# 配置解析
# ---------------------------------------------------------------------------
def test_parse_strips_quotes_and_comments():
    path = _tmp_env(
        '# 注释行\n'
        'LLM_MODEL="m 1"\n'
        "LLM_PROMPT='你好'\n"
        '\n'
        'LLM_TIMEOUT=30\n'
    )
    try:
        cfg = llm_probe.parse_env_file(path)
    finally:
        os.unlink(path)
    assert cfg == {"LLM_MODEL": "m 1", "LLM_PROMPT": "你好", "LLM_TIMEOUT": "30"}, cfg


def test_parse_rejects_empty_key():
    path = _tmp_env("=有值但没有键\n")
    try:
        assert _raises(llm_probe.parse_env_file, path), "空 KEY 没有被拒绝"
    finally:
        os.unlink(path)


def test_parse_rejects_malformed_line():
    path = _tmp_env("LLM_MODEL 没有等号\n")
    try:
        assert _raises(llm_probe.parse_env_file, path), "缺少 = 的行没有被拒绝"
    finally:
        os.unlink(path)


def test_parse_never_executes_value():
    marker = "/tmp/opencode/units_pwned"
    if os.path.exists(marker):
        os.unlink(marker)
    path = _tmp_env("LLM_MODEL=$(touch %s)\nLLM_BASE_URL=`id`\n" % marker)
    try:
        cfg = llm_probe.parse_env_file(path)
    finally:
        os.unlink(path)
    assert cfg["LLM_MODEL"] == "$(touch %s)" % marker, cfg
    assert not os.path.exists(marker), "配置值被当命令执行了"


# ---------------------------------------------------------------------------
# 加解密
# ---------------------------------------------------------------------------
def test_encrypt_decrypt_roundtrip():
    blob = llm_probe.encrypt_secret("sk-unit-roundtrip", "pw-单元测试")
    assert blob.startswith("enc:v1:"), blob[:16]
    assert llm_probe.decrypt_secret(blob, "pw-单元测试") == "sk-unit-roundtrip"


def test_wrong_passphrase_is_rejected():
    blob = llm_probe.encrypt_secret("sk-unit", "right")
    assert _raises(llm_probe.decrypt_secret, blob, "wrong"), "错误口令没有报错"


def test_corrupt_ciphertext_is_rejected():
    # 1) 非 base64
    assert _raises(llm_probe.decrypt_secret, "enc:v1:not-base64!!", "pw")
    # 2) 合法 base64 但内容不是 openssl 密文（缺 "Salted__" 头）
    junk = "enc:v1:" + base64.b64encode(b"X" * 32).decode()
    assert _raises(llm_probe.decrypt_secret, junk, "pw"), "垃圾密文没有报错"
    # 3) 密文被截断（padding 校验兜底）
    blob = llm_probe.encrypt_secret("sk-unit", "pw")
    cut = blob[:-6] + "AAAAAA"
    assert _raises(llm_probe.decrypt_secret, cut, "pw"), "截断密文没有报错"


def test_mask_secret_never_leaks():
    masked = llm_probe.mask_secret("sk-abcdefghijklmn")
    assert "sk-abcdefghijklmn" not in masked
    assert "efgh" not in masked, masked
    assert llm_probe.mask_secret("") == "(空)"
    assert llm_probe.mask_secret("short") == "*****"


def test_pkcs7_padding_roundtrip():
    for n in (1, 15, 16, 17, 32):
        data = b"A" * n
        padded = llm_probe._pkcs7_pad(data)
        assert len(padded) % 16 == 0, n
        assert llm_probe._pkcs7_unpad(padded) == data


def test_pkcs7_unpad_rejects_bad_padding():
    assert _raises(llm_probe._pkcs7_unpad, b"\x00" * 16), "全 0 padding 没被拒绝"
    assert _raises(llm_probe._pkcs7_unpad, b"A" * 16), "无 padding 没被拒绝"
    assert _raises(llm_probe._pkcs7_unpad, b""), "空输入没被拒绝"


def test_openssl_pbkdf2_capability_probe():
    value = llm_probe._openssl_pbkdf2_ok()
    assert isinstance(value, bool), value


# ---------------------------------------------------------------------------
# 结论映射（退出码契约）
# ---------------------------------------------------------------------------
def _step(name, ok, **extra):
    return dict(name=name, ok=ok, detail=extra.pop("detail", "d"), **extra)


def test_verdict_exit_codes():
    cases = [
        ("网络不通", [_step("L1 网络", False)], 2),
        ("认证失败", [_step("L1 网络", True), _step("L2 认证", False, kind="auth")], 3),
        ("限流", [_step("L1 网络", True), _step("L2 认证", False, kind="ratelimit")], 3),
        ("L2 网络类", [_step("L1 网络", True), _step("L2 认证", False, kind="timeout")], 2),
        ("路径不对", [_step("L1 网络", True), _step("L3 推理", False, kind="notfound")], 4),
        ("模型名不对", [_step("L1 网络", True), _step("L3 推理", False, kind="badrequest")], 4),
        ("推理限流", [_step("L1 网络", True), _step("L3 推理", False, kind="ratelimit")], 4),
        ("推理网络", [_step("L1 网络", True), _step("L3 推理", False, kind="refused")], 2),
        ("全部通过", [_step("L1 网络", True), _step("L2 认证", True),
                  _step("L3 推理", True, skipped=False)], 0),
        ("认证跳过(404不致命)", [_step("L1 网络", True),
                        _step("L2 认证", False, kind="notfound", fatal=False),
                        _step("L3 推理", True, skipped=False)], 0),
        ("只测网络", [_step("L1 网络", True)], 0),
        ("SDK 失败", [_step("L1 网络", True), _step("L2 认证", True),
                  _step("L4 SDK", False, fatal=True)], 5),
        ("L2 判死 + L3 跳过", [_step("L1 网络", True),
                      _step("L2 认证", False, kind="auth"),
                      _step("L3 推理", False, skipped=True,
                            detail="L2 认证未通过，已跳过（--all 可强制执行）")], 3),
    ]
    for label, steps, expect in cases:
        code, verdict = llm_probe.verdict_of(steps)
        assert code == expect, f"{label}: 期望 {expect} 实际 {code}（{verdict}）"
        assert isinstance(verdict, str) and verdict, label


# ---------------------------------------------------------------------------
# 密钥卫生
# ---------------------------------------------------------------------------
def test_passphrase_env_is_scrubbed():
    os.environ["LLM_PASSPHRASE"] = "unit-pw"

    class Args:
        passphrase = None

    try:
        got = llm_probe.read_passphrase(Args(), {})
        assert got == "unit-pw", got
        assert "LLM_PASSPHRASE" not in os.environ, "读到口令后仍留在环境变量里"
        # 子进程也不能再看到它
        out = subprocess.run(
            ["sh", "-c", "env | grep -c '^LLM_PASSPHRASE='"],
            capture_output=True, text=True, check=False,
        )
        assert out.stdout.strip() == "0", f"子进程继承了口令: {out.stdout}"
    finally:
        os.environ.pop("LLM_PASSPHRASE", None)


def test_api_key_env_is_scrubbed():
    os.environ["LLM_API_KEY"] = "sk-env-unit"

    class Args:
        key = None
        passphrase = None

    try:
        key, source = llm_probe.resolve_key(Args(), {})
        assert key == "sk-env-unit", key
        assert source == "环境变量 LLM_API_KEY", source
        assert "LLM_API_KEY" not in os.environ, "读到密钥后仍留在环境变量里"
    finally:
        os.environ.pop("LLM_API_KEY", None)


def test_secret_args_print_warning():
    for attr in ("key", "passphrase"):
        buf = io.StringIO()
        with contextlib.redirect_stderr(buf):
            llm_probe.warn_secret_arg(f"--{attr}")
        text = buf.getvalue()
        assert "--" + attr in text and "ps" in text, (attr, text)


def test_missing_passphrase_message_recommends_file_first():
    """拿不到口令时，提示要先推荐口令文件、并点明环境变量会被子进程继承。"""
    os.environ.pop("LLM_PASSPHRASE", None)
    os.environ["LLM_API_KEY_ENC"] = llm_probe.encrypt_secret("sk-x", "pw")
    path = _tmp_env("LLM_BASE_URL=https://api.openai.com/v1\n")

    class Args:
        key = None
        passphrase = None

    class _NoTTY:            # 避免在真 TTY 下触发交互式 getpass 把测试卡住
        def isatty(self):
            return False

        def read(self, *args, **kwargs):
            return ""

    saved_stdin = sys.stdin
    sys.stdin = _NoTTY()
    try:
        cfg = llm_probe.parse_env_file(path)
        try:
            llm_probe.resolve_key(Args(), cfg)
        except SystemExit as exc:
            text = str(exc)
            assert "LLM_PASSPHRASE_FILE" in text, text
            assert "继承" in text, text
            assert text.index("LLM_PASSPHRASE_FILE") < text.index("3)"), text
        else:
            raise AssertionError("拿不到口令时没有报错")
    finally:
        sys.stdin = saved_stdin
        os.unlink(path)
        os.environ.pop("LLM_API_KEY_ENC", None)


# ---------------------------------------------------------------------------
# 用户输入的错误必须变成"人话 + 退出码 1"，不能是 traceback，也不能占用 2
# （2 在本工具里是"网络不通"）
# ---------------------------------------------------------------------------
def test_read_config_turns_bad_config_into_exit_one():
    path = _tmp_env("LLM_MODEL 没有等号\n")
    saved = sys.stderr
    buf = io.StringIO()
    try:
        sys.stderr = buf
        try:
            llm_probe.read_config(path)
        except SystemExit as exc:
            assert exc.code == 1, exc.code
        else:
            raise AssertionError("畸形配置没有报错")
    finally:
        sys.stderr = saved
        os.unlink(path)
    assert "配置文件格式错误" in buf.getvalue(), buf.getvalue()


def test_argparse_usage_error_exits_one():
    """argparse 默认退出 2；不覆盖的话，CI 会把参数拼错当成网络故障。"""
    for argv in (["probe", "--timeout", "abc"], ["probe", "--no-such-flag"]):
        saved = sys.stderr
        buf = io.StringIO()
        try:
            sys.stderr = buf
            try:
                llm_probe.build_parser().parse_args(argv)
            except SystemExit as exc:
                assert exc.code == 1, f"{argv} → 退出码 {exc.code}"
            else:
                raise AssertionError(f"{argv} 没有报错")
        finally:
            sys.stderr = saved


def test_cmd_probe_rejects_non_positive_numbers():
    """显式 0 不能被 `args.x or ...` 当成"没传"而绕过校验。"""
    cfg = _tmp_env("LLM_BASE_URL=http://127.0.0.1:9/v1\nLLM_MODEL=m\n")
    try:
        for flag, value in (("--timeout", "0"), ("--max-tokens", "0"),
                            ("--max-tokens", "-1")):
            args = llm_probe.build_parser().parse_args(
                ["probe", "-c", cfg, "--key", "sk-x", flag, value])
            saved = sys.stderr
            buf = io.StringIO()
            try:
                sys.stderr = buf
                code = llm_probe.cmd_probe(args)
            finally:
                sys.stderr = saved
            assert code == 1, f"{flag} {value} → 退出码 {code}"
            assert "配置错误" in buf.getvalue(), buf.getvalue()
        # 非数字由 argparse 在解析阶段就拒（同样退出 1，见上一个测试）
        saved = sys.stderr
        try:
            sys.stderr = io.StringIO()
            try:
                llm_probe.build_parser().parse_args(
                    ["probe", "-c", cfg, "--key", "sk-x", "--timeout", "abc"])
            except SystemExit as exc:
                assert exc.code == 1, exc.code
            else:
                raise AssertionError("--timeout abc 没有被拒")
        finally:
            sys.stderr = saved
    finally:
        os.unlink(cfg)


def test_only_net_scrubs_api_key_env():
    os.environ["LLM_API_KEY"] = "sk-env-net"
    cfg = _tmp_env("LLM_BASE_URL=http://127.0.0.1:9/v1\nLLM_MODEL=m\n")
    try:
        args = llm_probe.build_parser().parse_args(
            ["probe", "-c", cfg, "--only", "net"])
        buf_out, buf_err = io.StringIO(), io.StringIO()
        try:
            with contextlib.redirect_stdout(buf_out), contextlib.redirect_stderr(buf_err):
                # 127.0.0.1:9 立刻拒绝，不产生外部流量；报告内容与本用例无关，吞掉
                llm_probe.cmd_probe(args)
        finally:
            pass
        assert "LLM_API_KEY" not in os.environ, "--only net 没摘环境变量"
    finally:
        os.unlink(cfg)
        os.environ.pop("LLM_API_KEY", None)


# ---------------------------------------------------------------------------
# JSON 输出 schema（与 sh 端字段对齐）
# ---------------------------------------------------------------------------
def test_json_schema_parity():
    result = {
        "version": "1.0",
        "base_url": "https://api.openai.com/v1",
        "model": "gpt-4o-mini",
        "key_masked": "sk-1********abc2 (len=16)",
        "key_source": "--key 参数",
        "config": "/tmp/x.env",
        "steps": [
            {"name": "L1 网络", "ok": True, "detail": "d"},
            {"name": "L2 认证", "ok": True, "detail": "d"},
            {"name": "L3 推理", "ok": True, "skipped": False, "detail": "d"},
        ],
        "verdict": "推理正常；认证通过",
        "exit_code": 0,
    }
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        llm_probe.print_report(result, as_json=True)
    parsed = json.loads(buf.getvalue())
    for field in ("version", "base_url", "model", "key_masked", "key_source",
                  "config", "steps", "verdict", "exit_code"):
        assert field in parsed, f"JSON 缺字段 {field}"
    assert parsed["exit_code"] == 0
    for step in parsed["steps"]:
        assert "name" in step and "ok" in step and "detail" in step, step
        assert isinstance(step["ok"], bool), step
    # L3 必须恒带 skipped（sh 端就是这么发的，两端才能 diff）
    assert "skipped" in parsed["steps"][2], parsed["steps"][2]


def test_default_config_template_uses_official_endpoint():
    """模板默认值不能指向第三方中转，避免用户照抄把密钥发给陌生服务。"""
    text = llm_probe.ENV_TEMPLATE
    base = [ln for ln in text.splitlines() if ln.startswith("LLM_BASE_URL=")]
    model = [ln for ln in text.splitlines() if ln.startswith("LLM_MODEL=")]
    assert base and base[0] == "LLM_BASE_URL=https://api.openai.com/v1", base
    assert model and model[0] == "LLM_MODEL=gpt-4o-mini", model


# ---------------------------------------------------------------------------
# 运行器
# ---------------------------------------------------------------------------
def main():
    tests = [(n, f) for n, f in sorted(globals().items())
             if n.startswith("test_") and callable(f)]
    failed = 0
    for name, fn in tests:
        try:
            fn()
        except Exception as exc:  # noqa: BLE001 —— 测试失败要给出完整原因
            failed += 1
            print(f"  ❌ {name}: {type(exc).__name__}: {exc}")
        else:
            print(f"  ✅ {name}")
    print(f"单元测试: {len(tests) - failed}/{len(tests)} 通过")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
