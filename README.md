# llm-probe

> 把"LLM 端点连不上"拆成四层来查：网络 → 认证 → 推理 → SDK。
> 两个零第三方依赖的实现（Python 标准库 / 纯 `curl` + `openssl`），退出码直接给结论，密钥加密存进 env 配置文件。

A layered connectivity prober for OpenAI-compatible LLM endpoints. Two dependency-free
implementations (Python stdlib and POSIX `curl`+`openssl`) that share one config file,
one ciphertext format and one exit-code contract.

## 为什么

写三行 `client.chat.completions.create()` 就能测连通性——但它挂了之后，你分不清是
DNS 挂了、key 过期了、`base_url` 少写了 `/v1`、模型名不对，还是 SDK 版本不兼容。
五种故障共用一个异常信息，只能一个个改着重跑。

`llm_probe` 每层一个独立请求、一个独立判定、一个独立的失败理由：

```text
[OK  ] L1 网络 [1/3]  DNS+TCP+TLS aiapiv2.pekpik.com:443 OK (153.3ms) TLSv1.3 CN=pekpik.com 有效期至 Nov 21 2026
[FAIL] L2 认证 [2/3]  HTTP 403：密钥无效
[SKIP] L3 推理 [3/3]  L2 认证未通过，已跳过（--all 可强制执行）
------------------------------------------------------------
结论 ❌ 认证失败：API Key 无效或已过期（HTTP 403：密钥无效）
退出码 3
```

## 快速开始

```bash
# 1) 生成配置（.llm_probe.env，权限 600）
python3 llm_probe.py init

# 2) 加密写入密钥（口令只走环境变量，不进配置文件、不进命令行）
export LLM_PASSPHRASE='你的口令'
python3 llm_probe.py setkey            # 或 --key sk-xxx

# 3) 分层探测
python3 llm_probe.py probe             # 不写 probe 也行
./llm_probe.sh probe --json            # 同一份配置、同一种密文、同一套退出码
```

没有配置文件也可以直接给参数，零副作用：

```bash
python3 llm_probe.py probe --base-url https://api.openai.com/v1 --model gpt-4o-mini
./llm_probe.sh probe --base-url https://api.openai.com/v1 --model gpt-4o-mini --only net
```

## 最简 demo

只想"发一条消息看看通不通"，看 [`demo_minimal.py`](demo_minimal.py)（85 行，含密钥读取与
openai 0.28 / 1.x 两套写法，真正发请求的调用只有几行）：

```python
client = OpenAI(base_url=BASE_URL, api_key=key, timeout=30)
resp = client.chat.completions.create(
    model=MODEL,
    messages=[{"role": "user", "content": "你好，请用一句话介绍你自己。"}],
)
print(resp.choices[0].message.content)
```

分层诊断、退出码、`--json` 这些才是本工具的正题，demo 不重复实现。

## 退出码

| 码 | 含义 | 典型证据 |
|---|---|---|
| `0` | 端点可用 | 推理层返回 200，报告里有回复 |
| `1` | 用法 / 配置错误 | base_url 非法、配置缺失、拿不到解密口令 |
| `2` | 网络不可达 | DNS 失败、连接拒绝、超时、TLS 失败 |
| `3` | 认证失败 | 401/403 无效的令牌、429 限流 |
| `4` | 推理失败 | 400 模型名错、404 路径错、429 限流、5xx |
| `5` | SDK 层失败 | 仅 `probe --sdk` |

```bash
if ./llm_probe.sh probe --json > result.json; then
    echo "端点可用"
else
    case $? in
        2) echo "网络问题，检查代理/防火墙" ;;
        3) echo "key 失效，去后台重新生成" ;;
        4) echo "参数问题，检查 base_url 或模型名" ;;
    esac
fi
```

## 项目结构

```text
llm-probe/
├── llm_probe.py            # 869 行，Python 3.7+，零第三方依赖，含 L4 SDK 层
├── llm_probe.sh            # 773 行，严格 POSIX（dash 验证），只依赖 curl + openssl
├── llm_probe.env.example   # 配置模板（init 会生成 .llm_probe.env，已 gitignore）
├── demo_minimal.py         # 最简 demo：单次 SDK 调用
├── docs/                   # 完整技术文章（含两份源码逐行附录）
├── skill/                  # OpenCode skill 副本（正本在 ~/.config/opencode/skills/）
├── tests/                  # mock 服务 + 27 项分支断言
├── README.md
└── .gitignore              # 忽略 .llm_probe.env、__pycache__
```

## 测试

```bash
./tests/run_tests.sh        # 需 curl、openssl、python3；短暂占用 18923 端口
# PASS=27 FAIL=0，退出码 0
```

10 组场景覆盖：正常端点、错误密钥、全站 401、路径 404、模型名 400、限流 429、
`/models` 不实现、端口未监听、DNS 失败、非法 scheme、**密文双向互通**、
**配置文件不被当代码执行**。测试刻意不读取真实配置的解密口令。

## 密钥安全

- 密文格式 `enc:v1:<base64(Salted__ + salt + 密文)>`，参数与
  `openssl enc -aes-256-cbc -pbkdf2 -iter 300000 -md sha256` 完全对齐，
  **Python 写的密文 shell 能解，反之亦然**。
- 口令来源优先级：环境变量 `LLM_PASSPHRASE` > `LLM_PASSPHRASE_FILE` 指向的文件（600）> 终端交互输入。
  **口令永远不写进配置文件。**
- 传给 openssl 时用 `-pass env:...`，口令不进命令行参数（否则 `ps` 可见）。
- 配置文件是数据不是脚本：两个实现都自己解析 `KEY=VALUE`，**不 `source`**，不执行任何一行。
- 报告里只输出打码后的密钥 `sk-xxx********xxxx (len=N)`。

## 文档

- [`docs/llm-probe-openai-endpoint-connectivity.md`](docs/llm-probe-openai-endpoint-connectivity.md)：完整技术文章——四层设计、退出码契约、密钥加密、mock 测试、真实端点排障实录，附两份源码逐行拆解。
- OpenCode skill 副本见 [`skill/llm-probe/SKILL.md`](skill/llm-probe/SKILL.md)。

## 边界

不负责跑业务对话，不做多轮压测或 TPOT/TTFT 性能评测，也不判断模型真伪。
