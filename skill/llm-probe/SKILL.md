---
name: llm-probe
version: 1.0.0
description: "OpenAI 兼容 LLM 端点连通性探测：把『不通』拆成 L1 网络(DNS/TCP/TLS)、L2 认证(401/403)、L3 推理(400/404/429)、L4 openai SDK(0.x/1.x 兼容) 四层，退出码直接给出结论。密钥从 .llm_probe.env 加密读取（enc:v1 + PBKDF2 口令），两个实现（python 标准库版 / 纯 curl+openssl 版）读同一份配置、密文互通、退出码一致。触发场景：用户问『这个 endpoint / API key 通不通』『401 无效的令牌』『连不上、超时、DNS 解析失败』『模型名不存在』『测一下 LLM 接口/中转站』，或要验证 base_url + key + model 三件套是否可用。反触发：真正要跑业务对话/生成内容时用正常 LLM 调用；查账单、查用量、创建 Endpoint 不归本 skill。"
metadata:
  requires:
    bins: ["curl", "openssl"]
---

# llm-probe：OpenAI 兼容端点分层连通性探测

两个实现，行为一致，按环境挑一个用。仓库根目录：`/home/yongchao/Workspace/VibeCoding/llm-probe/`（GitHub: <https://github.com/yongchaowu/llm-probe>）

| 脚本 | 路径 | 依赖 | 特点 |
|---|---|---|---|
| `llm_probe.py` | `~/Workspace/VibeCoding/llm-probe/llm_probe.py` | 仅 Python 标准库（3.7+） | 有 L4 SDK 层、`--json` 字段更全、TLS 证书信息 |
| `llm_probe.sh` | `~/Workspace/VibeCoding/llm-probe/llm_probe.sh` | `curl` + `openssl`（POSIX/dash 可跑） | 不依赖 Python；`\uXXXX` 解码有 python3 时自动启用 |
| `demo_minimal.py` | `~/Workspace/VibeCoding/llm-probe/demo_minimal.py` | openai SDK | 85 行单次调用示例，**不用于诊断** |

两者**共用** `~/Workspace/VibeCoding/llm-probe/.llm_probe.env`（600 权限，已 gitignore），
互写互读的密文格式完全一致。

## 快速开始

```bash
cd /home/yongchao/Workspace/VibeCoding/llm-probe

# 1) 生成配置（已存在则不要加 --force，避免覆盖用户配置）
python3 llm_probe.py init

# 2) 写入加密密钥（口令走环境变量，别用 --passphrase，会进 shell 历史）
export LLM_PASSPHRASE='你的口令'
python3 llm_probe.py setkey --key 'sk-xxx'      # 或不带 --key 交互输入

# 3) 分层探测（不写 probe 子命令也行）
python3 llm_probe.py probe
./llm_probe.sh probe --json                     # 机器可读，同一份配置
```

没有配置文件时，直接给参数即可，零副作用：

```bash
python3 llm_probe.py probe --base-url https://api.openai.com/v1 --model gpt-4o-mini
./llm_probe.sh probe --base-url https://api.openai.com/v1 --model gpt-4o-mini --only net
```

只要"发一条消息看通不通"、不需要分层诊断时，用 `demo_minimal.py`（85 行，含 openai 0.28 / 1.x 两套写法）；**可用性结论仍以 `probe` 的退出码为准**。

改过脚本之后跑回归：`./tests/run_tests.sh`，期望 `PASS=27 FAIL=0`（会短暂占用 18923 端口）。

## 分层与退出码（唯一权威判据）

| 退出码 | 含义 | 典型证据 |
|---|---|---|
| `0` | 通过 | L3 返回 `HTTP 200`，报告里有回复内容 |
| `1` | 用法/配置错误 | base_url 不是 http(s)、配置缺失、**拿不到解密口令** |
| `2` | 网络不可达 | DNS 解析失败 / 连接拒绝 / 超时 / TLS 握手失败 / 连接被重置 |
| `3` | 认证失败 | L2 `HTTP 401/403 无效的令牌`、限流 429 |
| `4` | 推理失败 | L3 `404 路径不对(多半是 base_url 缺 /v1)`、`400 模型名不对`、`429 限流`、`5xx` |
| `5` | SDK 层失败 | 仅 `probe --sdk`，openai 装了但调用报错 |

分层含义：

- **L1 网络**：裸 socket 发起 DNS→TCP→TLS，带出证书 CN / 有效期 / TLS 版本。天然不走代理。
- **L2 认证**：`GET {base}/models`。返回 404 时**标为非致命**（有的中转站不实现 /models），继续测 L3。
- **L3 推理**：`POST {base}/chat/completions`，单轮、`max_tokens` 默认 64。
- **L4 SDK**（仅 py）：`probe --sdk`，自动适配 `openai>=1.0` 新客户端与 `openai 0.28` 老 API。

L2 判定 key 有问题时默认跳过 L3（不白烧请求）；加 `--all` 强制执行。

## 常用命令

```bash
python3 llm_probe.py probe --json          # JSON 结果，exit_code 同时体现在退出码
python3 llm_probe.py probe --only net      # 只测网络（不需要口令）
python3 llm_probe.py probe --direct        # 绕开系统代理（http_proxy/透明 TUN 诊断时用）
python3 llm_probe.py env                   # 打印生效配置，密钥打码
python3 llm_probe.py showkey --plain       # 解密看明文（仅在用户明确要求时用）
./llm_probe.sh probe --only auth           # 只测认证
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

## 安全约束（务必遵守）

- **不要**把 `LLM_PASSPHRASE`、`LLM_API_KEY` 或 `showkey --plain` 的输出回显到会话里；
  需要贴报告时只贴打码后的 `sk-xxx********xxxx (len=N)`。
- 口令来源优先级：环境变量 `LLM_PASSPHRASE` > `LLM_PASSPHRASE_FILE` 指向的文件（600）> 终端交互输入。
  **口令永远不写进 `.llm_probe.env`**，否则加密形同虚设。
- 配置文件是数据不是脚本：两个实现都自己解析 `KEY=VALUE`，**不 `source`**，不执行任何一行。
- 配置文件权限应为 `600`；发现是 `644/664` 时提醒用户 `chmod 600`。
- 工具只向用户给定的 `base_url` 发请求，不会外联其它地址。

## 边界

- 不负责真正跑业务对话（那是正常 LLM 调用），也不做多轮压测、TPOT/TTFT 性能评测。
- 不判断模型真伪、不解释服务商返回的 `IsOfficial` 之类字段。
- `--sdk` 只验证 SDK 能不能打通，不比对各家 SDK 的功能差异。
