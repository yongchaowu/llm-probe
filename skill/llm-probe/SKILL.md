---
name: llm-probe
version: 1.1.0
description: "OpenAI 兼容 LLM 端点连通性与能力探测：把『不通』拆成 L1 网络(DNS/TCP/TLS)、L2 认证(401/403)、L3 推理(400/404/429)、L4 openai SDK(0.x/1.x 兼容) 四层；显式 --matrix 再验证 Chat Completions、Responses API、SSE streaming、tool calling、JSON schema。密钥从 .llm_probe.env 加密读取（enc:v1 + PBKDF2 口令），两个实现（python 标准库版 / 纯 curl+openssl 版）读同一份配置、密文互通、退出码一致。触发场景：用户问『这个 endpoint / API key 通不通』『401 无效的令牌』『连不上、超时、DNS 解析失败』『模型名不存在』『测一下 LLM 接口/中转站』，或要验证 base_url + key + model 三件套是否可用。反触发：真正要跑业务对话/生成内容时用正常 LLM 调用；查账单、查用量、创建 Endpoint 不归本 skill。"
metadata:
  requires:
    bins: ["curl", "openssl"]
---

# llm-probe：OpenAI 兼容端点分层连通性探测

两个实现，行为一致，按环境挑一个用。仓库根目录：`/home/yongchao/Workspace/VibeCoding/llm-probe/`（GitHub: <https://github.com/yongchaowu/llm-probe>）

| 脚本 | 路径 | 依赖 | 特点 |
|---|---|---|---|
| `llm_probe.py` | `~/Workspace/VibeCoding/llm-probe/llm_probe.py` | 仅 Python 标准库（3.7+） | 有 L4 SDK 层、`--matrix`、`--json` 字段更全、TLS 证书信息（1490 行） |
| `llm_probe.sh` | `~/Workspace/VibeCoding/llm-probe/llm_probe.sh` | POSIX shell + 常见 userland 工具、`curl` + `openssl` | 不依赖 Python；支持同一 `--matrix`（1434 行） |
| `demo_minimal.py` | `~/Workspace/VibeCoding/llm-probe/demo_minimal.py` | openai SDK | 97 行单次调用示例，**不用于诊断** |

两者**共用** `~/Workspace/VibeCoding/llm-probe/.llm_probe.env`（600 权限，已 gitignore），
互写互读的密文格式完全一致。

## 快速开始

```bash
cd /home/yongchao/Workspace/VibeCoding/llm-probe

# 1) 生成配置（已存在则不要加 --force，避免覆盖用户配置）
python3 llm_probe.py init

# 2) 写入加密密钥 —— 交互输入最稳（口令不进配置、不进 argv、不进 shell 历史）
python3 llm_probe.py setkey                     # 依次提示 API Key 和解密口令
#    非交互 / CI：key 走 stdin，口令走口令文件
#      export LLM_PASSPHRASE_FILE=~/.llm_probe_pass    # echo '口令' > 该文件 && chmod 600
#      printf '%s' "$KEY" | python3 llm_probe.py setkey
#    --key / --passphrase 会留在 shell 历史和 ps 进程列表里（脚本会打警告），仅临时测试用

# 3) 分层探测（不写 probe 子命令也行）
python3 llm_probe.py probe
./llm_probe.sh probe --json                     # 机器可读，同一份配置

# 可选：五项 OpenAI 兼容能力矩阵（chat / responses / SSE / tools / JSON schema）
python3 llm_probe.py probe --matrix --json
./llm_probe.sh probe --matrix --json
```

没有配置文件时，直接给参数即可，零副作用：

```bash
python3 llm_probe.py probe --base-url https://api.openai.com/v1 --model gpt-4o-mini
./llm_probe.sh probe --base-url https://api.openai.com/v1 --model gpt-4o-mini --only net
```

只要"发一条消息看通不通"、不需要分层诊断时，用 `demo_minimal.py`（97 行，含 openai 0.28 / 1.x 两套写法）；**可用性结论仍以 `probe` 的退出码为准**。

改过脚本之后跑回归：`./tests/run_tests.sh`，期望 `PASS=145 FAIL=0`（17 组场景，会短暂占用 18923 端口）；单元测试另跑 `python3 tests/test_units.py`（27 项）。CI（`.github/workflows/test.yml`）在每次 push/PR 上自动跑这两套。

## 分层与退出码（唯一权威判据）

| 退出码 | 含义 | 典型证据 |
|---|---|---|
| `0` | 通过 | L3 返回 `HTTP 200`；或 `--matrix` 全部通过/仅允许未实现能力 |
| `1` | 用法/配置错误 | base_url 不是 http(s)、配置缺失、**拿不到解密口令** |
| `2` | 网络不可达 | DNS 解析失败 / 连接拒绝 / 超时 / TLS 握手失败 / 连接被重置 |
| `3` | 认证失败 | L2 `HTTP 401/403 无效的令牌`、限流 429 |
| `4` | 推理 / 兼容失败 | L3 `404/400/429/5xx`；矩阵能力未实现、坏 SSE、坏 tool/schema |
| `5` | SDK 层失败 | 仅 `probe --sdk`，openai 装了但调用报错 |

分层含义：

- **L1 网络**：裸 socket 发起 DNS→TCP→TLS，带出证书 CN / 有效期 / TLS 版本。天然不走代理。
- **L2 认证**：`GET {base}/models`。返回 404 时**标为非致命**（有的中转站不实现 /models），继续测 L3。
- **L3 推理**：`POST {base}/chat/completions`，单轮、`max_tokens` 默认 64。
- **L4 SDK**（仅 py）：`probe --sdk`，自动适配 `openai>=1.0` 新客户端与 `openai 0.28` 老 API。

`--matrix` 是显式能力验收，不改变普通 probe：依次检查 Chat Completions、Responses API、
SSE streaming、tool calling、JSON schema。严格模式下任一能力未实现/响应畸形返回 `4`；
`--allow-unsupported` 只在 `chat_completions` 已通过时放宽可选能力的 404/405；400、错误路径、
全端点失败、认证、网络、限流和坏 200 仍失败。最多发五次生成请求，`LLM_PROMPT` 不会改写固定探针。

L2 判定 key 有问题时默认跳过 L3（不白烧请求）；加 `--all` 强制执行。

## 常用命令

```bash
python3 llm_probe.py probe --json          # JSON 结果，exit_code 同时体现在退出码
python3 llm_probe.py probe --only net      # 只测网络（不需要口令）
python3 llm_probe.py probe --direct        # 绕开系统代理（http_proxy/透明 TUN 诊断时用）
python3 llm_probe.py env                   # 打印生效配置，密钥打码
python3 llm_probe.py showkey --plain       # 解密看明文（仅在用户明确要求时用）
./llm_probe.sh probe --only auth           # 只测认证
python3 llm_probe.py probe --matrix --json # 五项兼容能力矩阵
./llm_probe.sh probe --matrix --allow-unsupported --json
```

## 排障对照表

| 现象（报告里的结论） | 判定 | 下一步 |
|---|---|---|
| `DNS 解析失败` | 域名不存在 / 无网 | 核对 base_url 拼写 |
| `连接被拒绝（端口没开）` | 端口错 | 检查是否应为 443 / 是否少写了端口 |
| `TLS 失败 / 连接被重置` | 代理或防火墙中途掐断 | 加 `--direct` 复测；确认 TUN/VPN 状态 |
| `HTTP 401/403 无效的令牌` | **key 失效** | 去服务商后台重新生成 key 后 `setkey` |
| `HTTP 404 ... 检查 base_url 是否含 /v1` | 路径错 | base_url 要含 `/v1` |
| `HTTP 400 ... 多半是模型名不对` | model 错 | 核对模型名（中转站常用自定义命名） |
| `HTTP 429 限流/额度耗尽` | 余额或限流 | 查余额、稍后重试 |
| `认证跳过（/models 404）` | 中转站不实现 models | 属正常，以 L3 为准 |
| `推理正常；认证通过` | 三件套可用 | 收工 |

## 容易踩的坑（都是实测出来的）

- **退出码 2 只能表示"网络不通"**。参数错误、配置畸形、`--timeout 0` 都要退 1 并说清原因；
  改 argparse 时记得它默认退 2，会把 CI 的分诊带歪。
- **配置里显式写 0 不会被当成"没传"**。写 `args.x or cfg.get(...)` 就会把 `--max-tokens 0`
  悄悄换成默认值；要判断 `is not None`。
- **摘除环境变量不能只做在"读密钥"那条路上**。`--only net` 不读密钥，但环境里的
  `LLM_API_KEY` 照样会被 curl 继承；`--key` 给了以后环境里那份也多余。
- **shell 的 case 模式别被转义搞坏**：写 `\"*`（转义双引号），别写 `'"'"'"*`
  （那是转义事故，实际匹配"单引号+双引号"），否则所有双引号配置值都带着引号往下走。
- **awk 拿非数字字段跟数字比较会走字符串比较**：`"abc" > "0"` 为真。校验要先用 `case`
  卡字符类，再用 awk 比数值。
- **`read` 遇到"有内容但没换行"的 EOF 会返回非 0**，但变量已经拿到了——不能只看返回值。

## 安全约束（务必遵守）

- **不要**把 `LLM_PASSPHRASE`、`LLM_API_KEY` 或 `showkey --plain` 的输出回显到会话里；
  需要贴报告时只贴打码后的 `sk-xxx********xxxx (len=N)`。
- 口令来源**按推荐顺序**（口令本身永远不写进 `.llm_probe.env`，否则加密形同虚设）：
  1. `LLM_PASSPHRASE_FILE` 指向的口令文件（600）—— **非交互首选**
  2. 终端交互输入 —— 最安全
  3. 环境变量 `LLM_PASSPHRASE` —— 权宜之计：**会被所有子进程继承**，脚本读到后会立刻
     从自己环境里摘掉（sh 端用 `VAR=val cmd` 只喂给 openssl 那一条命令）
  - `--passphrase` / `--key` 会进 shell 历史和 `ps` 进程列表，两个实现都会打 stderr 警告，
    仅用于临时测试；密钥的非交互入口是 stdin（`printf '%s' "$KEY" | ... setkey`）。
- shell 版把 `Authorization` 放入 0700 临时目录中的 header 文件，通过 `curl -H @file` 传递，不把 key 放进 curl argv / `ps`。
- Python HTTP opener 拒绝跨 origin 重定向；shell 默认不跟随重定向，避免 bearer token 被转发到第三方。
- shell 版依赖 **OpenSSL ≥ 1.1.1**（`-pbkdf2` 是 1.1.1 才有的选项，LibreSSL 不支持），
  启动时做功能探测，不支持会给出可读报错；Python 端装了 `cryptography` 就不依赖 openssl。
- 配置文件是数据不是脚本：两个实现都自己解析 `KEY=VALUE`，**不 `source`**，不执行任何一行。
- 配置文件权限应为 `600`；发现是 `644/664` 时提醒用户 `chmod 600`。
- 工具只向用户给定的 `base_url` 发请求，不会外联其它地址。

## 边界

- 不负责真正跑业务对话（那是正常 LLM 调用），也不做多轮压测、TPOT/TTFT 性能评测；`--matrix` 只验证固定兼容能力，不评估模型质量或供应商真伪。
- 不判断模型真伪、不解释服务商返回的 `IsOfficial` 之类字段。
- `--sdk` 只验证 SDK 能不能打通，不比对各家 SDK 的功能差异。
