# llm-probe

> 把"LLM 端点连不上"拆成四层来查：网络 → 认证 → 推理 → SDK。
> 两个零第三方依赖的实现（Python 标准库 / 纯 `curl` + `openssl`），退出码直接给结论，密钥加密存进 env 配置文件。
> 需要验证 OpenAI 兼容能力时，再显式运行五项 `--matrix` 能力矩阵。

A layered connectivity prober for OpenAI-compatible LLM endpoints. Two dependency-free
implementations (Python stdlib and POSIX `curl`+`openssl`) that share one config file,
one ciphertext format and one exit-code contract. An opt-in `--matrix` mode checks five
OpenAI capability shapes without changing the default probe.

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

# 2) 加密写入密钥 —— 交互输入，推荐（口令不进配置、不进命令行、不进 shell 历史）
python3 llm_probe.py setkey
#    CI / 非交互则换成：密钥走 stdin（不进 argv、不进历史），口令走口令文件
#      export LLM_PASSPHRASE_FILE=~/.llm_probe_pass   # echo '口令' > 该文件 && chmod 600
#      printf '%s' "$KEY" | python3 llm_probe.py setkey

# 3) 分层探测（口令来源见下面「密钥安全」的权衡表）
python3 llm_probe.py probe                          # 不写 probe 也行
./llm_probe.sh probe --json                         # 同一份配置、同一种密文、同一套退出码

# 可选：验证 chat / responses / streaming / tools / json_schema 五项兼容性
python3 llm_probe.py probe --matrix --json
./llm_probe.sh probe --matrix --json
```

> `--key sk-xxx` / `--passphrase '口令'` 会留在 **shell 历史** 和 **`ps` 进程列表** 里，
> 仅建议临时测试使用；两个实现都会对它们打一行 stderr 警告。

没有配置文件也可以直接给参数，零副作用：

```bash
python3 llm_probe.py probe --base-url https://api.openai.com/v1 --model gpt-4o-mini
./llm_probe.sh probe --base-url https://api.openai.com/v1 --model gpt-4o-mini --only net
```

## 最简 demo

只想"发一条消息看看通不通"，看 [`demo_minimal.py`](demo_minimal.py)（97 行，含密钥读取与
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

## OpenAI 兼容能力矩阵

`--matrix` 是显式的第二层工作流，不会改变普通 `probe` 的请求数量或报告结构。它针对同一组
`(base_url, model, key)` 依次验证五个能力单元：

1. `chat_completions`：非流式 Chat Completions，响应必须有非空文本；
2. `responses_api`：`POST /responses`，支持 reasoning item 先于文本的响应；
3. `streaming_sse`：`text/event-stream`、有效 chunk、文本 delta 和终止 `[DONE]`；
4. `tool_calling`：现代 `tool_calls`、`finish_reason=tool_calls`、合法 JSON arguments；
5. `json_schema`：`response_format.type=json_schema` 的严格固定 schema 输出。

```bash
python3 llm_probe.py probe --matrix
python3 llm_probe.py probe --matrix --json > compatibility.json
```

矩阵使用固定的最小请求，不读取 `LLM_PROMPT` 改写探针提示词；`LLM_MAX_TOKENS` 和
`LLM_TIMEOUT` 仍生效，因此最多可能发出五次生成请求。报告只保存能力结论，不保存模型原文、
tool arguments 或 SSE body。404/405 表示该能力未实现，严格模式返回 `4`；`--allow-unsupported`
只允许在 `chat_completions` 已通过时放宽这些可选能力，400、错误路径、全端点失败、网络、
认证、限流和畸形 200 响应仍然失败。`--all` 可强制在认证/限流失败后继续发完剩余矩阵请求。

`--json` 保留原有顶层字段，并增加：

```json
{
  "mode": "compatibility",
  "summary": {"passed": 5, "failed": 0, "skipped": 0, "total": 5},
  "steps": [{"id": "chat_completions", "ok": true, "status": 200}]
}
```

矩阵是能力验收，不是性能基准：它不计算 TTFT/TPOT，也不做并发压测。


| 码 | 含义 | 典型证据 |
|---|---|---|
| `0` | 端点可用 | 推理层返回 200；或矩阵全部通过/仅允许的未实现能力 |
| `1` | 用法 / 配置错误 | base_url 非法、配置缺失、拿不到解密口令 |
| `2` | 网络不可达 | DNS 失败、连接拒绝、超时、TLS 失败 |
| `3` | 认证失败 | 401/403 无效的令牌、429 限流 |
| `4` | 推理 / 兼容失败 | 400 模型名错、404 路径错、429、5xx；矩阵能力不支持或响应畸形 |
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
├── llm_probe.py            # 1490 行，Python 3.7+，零第三方依赖，含 L4 SDK 与兼容矩阵
├── llm_probe.sh            # 1434 行，POSIX shell + 常见 userland 工具、curl + openssl
├── llm_probe.env.example   # 配置模板（init 会生成 .llm_probe.env，已 gitignore）
├── demo_minimal.py         # 97 行最简 demo：单次 SDK 调用
├── docs/                   # 完整技术文章（含两份源码逐行附录）
├── skill/                  # OpenCode skill 副本（正本在 ~/.config/opencode/skills/）
├── tests/
│   ├── run_tests.sh        # 17 组场景、145 项断言（含 py/sh probe 与矩阵 JSON 一致性）
│   ├── test_units.py       # 27 项单元测试：配置 / 加解密 / 结论 / 矩阵解析 / 密钥卫生
│   └── mock_llm.py         # 基础故障 + matrix_* 兼容变体的 mock 服务
├── README.md
├── .gitignore              # 忽略 .llm_probe.env、__pycache__
└── .github/workflows/       # CI：push/PR 自动跑上面两套测试
```

## 测试

```bash
./tests/run_tests.sh        # 需 curl、openssl、python3；短暂占用 18923 端口
# PASS=145 FAIL=0，退出码 0
python3 tests/test_units.py # 27 项单元测试也能单独跑（或用 pytest）
```

17 组场景覆盖：正常端点、错误密钥、全站 401、路径 404、模型名 400、限流 429、
`/models` 不实现、端口未监听、DNS 失败、非法 scheme、**密文双向互通**、
**配置文件不被当代码执行**、**口令不泄漏给子进程**、**setkey 走 stdin**、
**老 openssl 报错**、**py/sh 逐字段一致（退出码 + 步骤 + 结论 + L2/L3 detail + schema，6 种故障模式）**、
**五项兼容矩阵**（支持、404、缺 `[DONE]`、坏 tool/schema、畸形 200、超大响应、连接重置、认证 gate、无 Python PATH）、
**自查发现的缺陷回归**（退出码契约、0 值绕过校验、畸形配置、双引号剥离、`~` 展开、
`--only net` 泄漏、优先级是否真的到了服务端……）。
测试刻意不读取真实配置的解密口令。

`.github/workflows/test.yml` 在每次 push/PR 上跑同一套用例（ubuntu 用 dash、
macos 用系统 sh，顺带验证 BSD 用户态工具链），并检查 `.llm_probe.env` 没被提交。

## 密钥安全

- 密文格式 `enc:v1:<base64(Salted__ + salt + 密文)>`，参数与
  `openssl enc -aes-256-cbc -pbkdf2 -iter 300000 -md sha256` 完全对齐，
  **Python 写的密文 shell 能解，反之亦然**。
- 口令本身**永远不写进配置文件**，传给 openssl 时用 `-pass env:...`，
  口令不进命令行参数（否则 `ps` 直接可见）。
- **口令从哪来**（脚本读到环境变量里的口令后，会立刻把它从自己的环境里摘掉，
  这样后续子进程就再也拿不到）：

  | 来源 | 泄露面 | 适用场景 |
  |---|---|---|
  | `LLM_PASSPHRASE_FILE` 指向的文件（600） | 只有文件权限 | **非交互 / CI 首选** |
  | 终端交互输入（`getpass` / `stty -echo`） | 只在内存里过一遍 | **最安全** |
  | 环境变量 `LLM_PASSPHRASE` | 会被子进程继承（读到即摘，仍有短暂窗口） | 权宜之计 |
  | `--passphrase` 参数 | **shell 历史 + `ps` 进程列表** | 仅临时测试（会打警告） |

- 密钥同理：`setkey` 支持从 **stdin 管道**读（`printf '%s' "$KEY" | ... setkey`），
  不进 argv、不进历史；`--key` 会打 stderr 警告。
- 报告里只输出打码后的密钥 `sk-xxx********xxxx (len=N)`。
- shell 版把 `Authorization` 写入临时私有 header 文件，再以 `curl -H @file` 读取；密钥不进入 curl argv / `ps`。
- Python HTTP opener 拒绝跨 origin 重定向，避免把 bearer token 转发到第三方；shell 默认不跟随重定向。
- 不只是"读到才摘"：选了 `--key` 就把环境里的 `LLM_API_KEY` 一并摘掉；
  `--only net` 这种**根本不读密钥**的路径也会摘——否则它照样会被 curl 继承。
- **退出码契约不许被占用**：`2` 永远表示"网络不通"。参数拼错（argparse 默认退 2）、
  配置畸形、`--timeout 0` 这类问题一律退 `1` 并给出可读原因，不吐 traceback。
- **配置是数据**：两个实现都自己解析（剥引号、展开 `~`、拒绝空 KEY 与非 `KEY=VALUE` 行、
  校验 timeout/max-tokens 为正数），**不 `source`**，不执行任何一行；坏配置两端都退 1 并指出行号。
- **优先级只有一条**：`命令行 > 环境变量 > 配置文件`。两个实现一致，并且由 mock 在
  **服务端**校验 `max_tokens`，确保优先级真的上了线，而不是只改了本地变量。

### 两个实现的有意差异

| 维度 | `llm_probe.py` | `llm_probe.sh` |
|---|---|---|
| L1 报告 | 证书 CN、有效期、TLS 版本 | `remote_ip`、连接/握手耗时拆分（curl 拿不到证书链） |
| `\uXXXX` 解码 | 原生 | 有 python3 时解码，没有就原样返回 |
| L4 SDK | 支持 | 不支持（提示改用 py 版） |
| `--matrix` | 支持五项 OpenAI 能力矩阵 | 支持同一矩阵，仍不依赖 Python |

**其余全部逐字段一致**：退出码、每个步骤的 `ok`/`skipped`、结论文字、L2/L3 的 detail、
`--json` 字段集合——由第 15 组测试在 6 种故障模式上逐项比对。
- 配置文件是数据不是脚本：两个实现都自己解析 `KEY=VALUE`（支持引号、拒绝空键），
  **不 `source`**，不执行任何一行。

## 兼容性

| 实现 | 要求 | 说明 |
|---|---|---|
| `llm_probe.py` | Python 3.7+，**零第三方依赖** | 装了 `cryptography` 会优先走它；否则回退 `openssl` CLI |
| `llm_probe.sh` | POSIX shell 语法（dash/bash/zsh）+ 常见 userland 工具、`curl`、`openssl ≥ 1.1.1` | `-pbkdf2` 是 1.1.1 才加的；LibreSSL 不支持，启动时做功能探测并给出可读报错 |

配置文件、密文格式、退出码契约、`--json` 字段三者在两端**完全一致**，
由 `tests/run_tests.sh` 第 15 组逐字段比对。

> shell 版**刻意不用 `set -e`**：本工具的核心是"抓住 curl 的非零退出码来分类故障"，
> `set -e` 会在第一个失败的 `err=$(curl ...)` 处直接中止——端口不通时一行报告都打不出来，
> 只剩 curl 的原始退出码 7。关键命令的状态都在脚本里显式判断，由测试兜底。

## 文档

- [`docs/llm-probe-openai-endpoint-connectivity.md`](docs/llm-probe-openai-endpoint-connectivity.md)：完整技术文章——四层设计、退出码契约、密钥加密、mock 测试、真实端点排障实录，附两份源码逐行拆解。
- OpenCode skill 副本见 [`skill/llm-probe/SKILL.md`](skill/llm-probe/SKILL.md)。

## 边界

不负责跑业务对话，不做多轮压测或 TPOT/TTFT 性能评测，也不判断模型真伪。
`--matrix` 只验证固定的 OpenAI 兼容能力形状，不把能力通过解释成模型质量、供应商官方性或
生产性能保证；benchmark、fingerprinting 和 agent readiness 仍属于后续工作。
