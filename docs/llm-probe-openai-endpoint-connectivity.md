---
title: LLM 端点连不上？把"不通"拆成四层来查：llm_probe 的 py + sh 双实现
description: 从一次 401 无效的令牌说起，讲清楚 OpenAI 兼容端点要打通要过几关（DNS/TCP/TLS、/models 认证、/chat/completions 推理、openai 0.28 与 1.x 兼容），并给出零依赖 Python 与纯 curl 两个实现：退出码直接给结论，密钥用 openssl 加密后存进 env 配置文件，附 mock 服务跑出的 44 项断言。
date: 2026-09-25
tags: [Python, Shell, LLM, 网络诊断, 密钥安全, OpenAI, curl]
lang: zh-CN
---

# LLM 端点连不上？把"不通"拆成四层来查：llm_probe 的 py + sh 双实现

排查一个中转站的 LLM 接口时，我常常只写三行就跑起来了：

```python
from openai import OpenAI
client = OpenAI(base_url="https://aiapiv2.pekpik.com/v1", api_key="sk-xxx")
print(client.chat.completions.create(model="claude-opus-4-7",
      messages=[{"role": "user", "content": "Olá!"}]).choices[0].message.content)
```

> `aiapiv2.pekpik.com` 是本文真实排障对象——一个**第三方中转站**，仅作示例。
> `llm_probe` 自己的默认值是官方 `https://api.openai.com/v1`，任何 OpenAI 兼容端点都能填。

然后它挂了。挂了之后我开始瞎猜：是网络不通？是 key 过期了？是 base_url 少写了 `/v1`？是模型名不对？还是 SDK 版本不兼容？——**一个异常信息回答不了这五个问题中的任何一个**，只能一个个改着重跑，每轮几分钟。

更糟的是第二类问题：key 明文躺在脚本里，脚本进了备份、进了网盘、贴进了聊天窗口，key 就等于公开了。

这篇文章对应两个文件：`llm_probe.py`（974 行，纯标准库）和 `llm_probe.sh`（851 行，纯 `curl` + `openssl`）。它们做同一件事——**把"连不上"翻译成"哪一层连不上"**，用退出码直接给结论；并且把密钥加密存进一份 env 配置文件，两个实现互认对方写的密文。

完整代码在 GitHub：<https://github.com/yongchaowu/llm-probe>，本地位于 `~/Workspace/VibeCoding/llm-probe/`。仓库里还有一份"最简 demo"（`demo_minimal.py`，97 行），见第六节；本文附录收录了两份脚本的逐行源码。

---

## 目录

- [一、起因：异常信息回答不了"哪一层坏了"](#一一起因异常信息回答不了哪一层坏了)
- [二、四层探测：每一层各自回答一个问题](#二四层探测每一层各自回答一个问题)
  - [L1 网络：DNS → TCP → TLS](#l1-网络dns--tcp--tls)
  - [L2 认证：GET /models](#l2-认证get-models)
  - [L3 推理：POST /chat/completions](#l3-推理post-chatcompletions)
  - [L4 SDK：0.28 和 1.x 是两个世界](#l4-sdk028-和-1x-是两个世界)
- [三、退出码就是结论](#三退出码就是结论)
- [四、实测：用 mock 服务把分支跑干净](#四实测用-mock-服务把分支跑干净)
- [五、密钥：加密后存进 env 文件](#五密钥加密后存进-env-文件)
- [六、只想要一个最简 demo](#六只想要一个最简-demo)
- [七、两个实现怎么保持行为一致](#七两个实现怎么保持行为一致)
- [八、真实端点排障实录](#八真实端点排障实录)
- [九、可以怎么改](#九可以怎么改)
- [总结](#总结)
- [附录：完整源码](#附录完整源码)

---

## 一、起因：异常信息回答不了"哪一层坏了"

一个 OpenAI 兼容端点要真正可用，得依次通过四道关卡，而**每道关卡的失败长得完全不一样**：

1. 域名能解析吗？TCP 能握手吗？TLS 证书有效吗？
2. 这个 key 还活着吗？
3. 这个模型名服务端认吗？请求参数能被接受吗？
4. 我用的 openai SDK 版本，跟这个端点兼容吗？

写死一个 `client.chat.completions.create()` 的脚本，把四道关卡压成了一个点：任何一道挂了，你看到的都是同一个 `APIConnectionError` 或者一行 401。于是排障退化成猜谜。

`llm_probe` 的核心思路是**分层**：每层一个独立请求、一个独立判定、一个独立的失败理由，串起来跑一遍，报告里直接写"卡在第几层、证据是什么"。

```
[OK  ] L1 网络 [1/3]  DNS+TCP+TLS aiapiv2.pekpik.com:443 OK (153.3ms) TLSv1.3 CN=pekpik.com 有效期至 Nov 21 17:25:02 2026 GMT
[FAIL] L2 认证 [2/3]  HTTP 403：密钥无效
[SKIP] L3 推理 [3/3]  L2 认证未通过，已跳过（--all 可强制执行）
------------------------------------------------------------
结论 ❌ 认证失败：API Key 无效或已过期（HTTP 403：密钥无效）
退出码 3
```

上面这段是真实输出：网络完全正常、证书没问题，卡在第二层。**这比我原来那三行脚本给出的信息多，而且结论是机器可判断的（退出码 3）**——可以直接写进 CI 或者 shell 的 `if` 里。

## 二、四层探测：每一层各自回答一个问题

### L1 网络：DNS → TCP → TLS

不发 HTTP 请求，直接开 socket：先解析域名，再 TCP 连接，再做一次 TLS 握手，并把证书信息带出来（签发给谁、什么时候过期、TLS 协议版本）。

```python
context = ssl.create_default_context()
with context.wrap_socket(sock, server_hostname=host) as tls:
    cert = tls.getpeercert() or {}
    subject = dict(x[0] for x in cert.get("subject", ())).get("commonName", "?")
```

这一层值得单独存在的理由有三个：

- **错误可以精确分类**：`socket.gaierror` 是 DNS、`ConnectionRefusedError` 是端口没开、超时是被防火墙丢包、`SSLError` 是证书问题。这四种在 HTTP 层看起来都像"连不上"。
- **证书快过期能提前发现**：`notAfter` 直接打在报告里。
- **它是裸 socket，天然不走系统代理**——所以我在两个实现里都加了 `--direct`，让后面的 HTTP 层也绕开代理，保持口径一致。不然会出现"L1 说通、L2 说不通"的自相矛盾结论（真遇到过，见第七节）。

shell 版没有 `ssl` 模块可用，就用 curl 的写法拿同样的信息：

```sh
curl "$@" -o /dev/null -w '%{time_connect} %{time_appconnect} %{remote_ip}' "$BASE_URL/"
```

`time_appconnect` 是 TLS 握手耗时（走代理时它等于代理到目标的握手），`remote_ip` 能一眼看出流量是不是被 TUN 劫走了。

### L2 认证：GET /models

```http
GET {base_url}/models
Authorization: Bearer {key}
```

`/models` 是 OpenAI 兼容端点里最轻的鉴权入口，不产生 token 消耗。判定规则：

| 状态码 | 判定 | 是否致命 |
|---|---|---|
| 200 | key 有效，顺手数一下可枚举的模型数 | — |
| 401 / 403 | **key 无效或已过期** | 致命，退出码 3 |
| 404 | 这个中转站没实现 `/models` | **非致命**，继续测 L3 |
| 429 | 限流或额度耗尽 | 致命，退出码 3 |
| 5xx | 服务端故障 | 致命 |

**404 必须是非致命的**，这是我踩过的坑：不少 new-api / one-api 架构的中转站对 `/models` 返回 404，但 `/chat/completions` 完全正常。如果把 404 当成失败，这类端点会被误判成"不可用"。对应报告里会打一行 `认证跳过（HTTP 404：该端点未实现 /models）`，最终结论仍可能是 0。

还有一处刻意的"偷懒"：L2 判定 key 有问题之后，**默认跳过 L3**（`L2 认证未通过，已跳过`）。反正 L3 一定也会 401，何必白烧一次请求、多等一秒？要强制跑完就加 `--all`。

### L3 推理：POST /chat/completions

单轮、短提示、`max_tokens` 默认 64——这是"能不能推理"的最小证明，不是压测。判定：

| 状态码 | 结论 | 退出码 |
|---|---|---|
| 200 | 打通，报告里打印回复片段和 token 用量 | 0 |
| 400 | **模型名不被接受**（`model does not exist`） | 4 |
| 404 | 路径不对，提示"检查 base_url 是否含 /v1" | 4 |
| 429 | 限流 / 额度耗尽 | 4 |
| 401 / 403 | key 问题漏到这层才暴露 | 3 |

其中 400 和 404 的区分很有价值：**同样是"请求发出去了但没成"，400 指向 model，404 指向 URL**，两者的修法完全不同。

### L4 SDK：0.28 和 1.x 是两个世界

这一层只在加 `--sdk` 时执行，因为它要真实调一次 SDK，不是免费的。它的存在理由很具体：这台机器上装的是 `openai 0.28.1`，而脚本里写的是新版写法：

```python
from openai import OpenAI          # 0.28.1 根本没有这个类
ImportError: cannot import name 'OpenAI' from 'openai'
```

**请求根本没发出去**，却看起来像"端点不通"。这类假阴性最难查。所以 L4 会先报 SDK 版本和走的分支，再报调用结果：

```python
if hasattr(openai, "OpenAI"):          # >= 1.0 新客户端
    client = openai.OpenAI(base_url=..., api_key=..., timeout=...)
    ...
else:                                   # 0.28 老 API
    openai.api_base = base_url
    openai.api_key = key
    resp = openai.ChatCompletion.create(..., request_timeout=timeout)
```

实测输出：`openai 0.28.1（0.x 老 API）调用成功 (xxms)`。SDK 完全没装时，这一层标记为非致命的 `未安装 openai SDK`，不影响 0 的结论。

## 三、退出码就是结论

| 退出码 | 含义 | 典型证据 |
|---|---|---|
| `0` | 端点可用 | L3 返回 200，报告里有回复 |
| `1` | 用法 / 配置错误 | base_url 不是 http(s)、配置缺失、拿不到解密口令 |
| `2` | 网络不可达 | DNS 失败、连接拒绝、超时、TLS 失败、连接被重置 |
| `3` | 认证失败 | 401/403 无效的令牌、429 限流 |
| `4` | 推理失败 | 400 模型名、404 路径、429 限流、5xx |
| `5` | SDK 层失败 | 仅 `probe --sdk` |

退出码是这套工具最重要的接口。有了它，排障脚本能写成：

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

`--json` 输出里同样带 `exit_code`、`verdict`、每层的 `detail`，方便存档或者喂给别的程序。

## 四、实测：用 mock 服务把分支跑干净

**结论要可信，得先在自己能控制的环境里把所有分支跑一遍。** 于是写了个 ~100 行的 mock 服务（`MOCK_MODE` 切换行为），覆盖 15 组场景、44 项断言：

| # | 场景 | 期望退出码 | py | sh |
|---|---|---|---|---|
| 1 | 正常端点（密钥正确） | 0 | ✅ | ✅ |
| 1 | 错误密钥 | 3 | ✅ | ✅ |
| 1 | `--json` 输出是合法 JSON | 0 | ✅ | ✅ |
| 1 | `--sdk` 走 0.28 老 API 分支 | 0 | ✅ | ✅ |
| 2 | 全站 401 | 3 | ✅ | ✅ |
| 2 | `--all` 强制跑 L3 | 3 | ✅ | — |
| 3 | 路径 404 | 4 | ✅ | ✅ |
| 4 | 模型名 400 | 4 | ✅ | ✅ |
| 5 | 限流 429 | 4 | ✅ | ✅ |
| 6 | `/models` 404 但推理正常 | 0 | ✅ | ✅ |
| 7 | 端口未监听 / DNS 失败 | 2 | ✅ | ✅ |
| 8 | 非法 scheme（`ftp://`） | 1 | ✅ | ✅ |
| 9 | 密文互通（sh 写 py 解、py 写 sh 解） | 0 | ✅ | ✅ |
| 9 | 错误口令必须失败 | 1 | ✅ | ✅ |
| 10 | 配置文件里的 `$(...)` 不被执行 | — | ✅ | ✅ |
| 11 | 口令不泄漏给子进程（curl 看不到、openssl 拿得到） | — | ✅ | ✅ |
| 12 | `setkey` 走 stdin / 非交互无输入报错 | 1 | ✅ | ✅ |
| 13 | 老 openssl（无 `-pbkdf2`）给出可读报错 | 1 | ✅ | ✅ |
| 14 | 单元测试（配置解析 / 加解密 / 结论映射 / 密钥卫生） | — | ✅ | — |
| 15 | py / sh 跨实现逐字段一致（6 种故障模式） | 0/2/3/4 | ✅ | ✅ |

全绿。**测试过程中挖出三个真 bug**，都是"写的时候觉得对、跑起来才露馅"的类型：

**其一，`$(...)` 子 shell 丢赋值。** shell 版最初这么写分类函数：

```sh
STEP2_KIND=$(classify_curl_error)      # ← 函数里 LAST_CURL_MSG="..." 赋值丢了
STEP2_DETAIL=$LAST_CURL_MSG            # ← 于是 detail 是空的
```

`$( )` 会在子 shell 里执行，函数对外只留下 stdout，内部的变量赋值全部作废。表现是报告里 L2 那行 `detail` 空白、结论变成"网络不可达："（空）。改成直接调用函数、用两个全局变量传出结果就好了。这个 bug 的隐蔽之处在于**退出码是对的，只有文案是空的**，肉眼扫一遍很容易放过。

**其二，mock 返回 `\u56de\u590d`，sed 抓出来是字面量。** Python 的 `json.dumps` 默认 `ensure_ascii=True`，中文全被转成 `\uXXXX`。shell 版用 `sed` 抽 `"content"` 字段，拿到的是 `mock \u56de\u590d...`，`grep "mock 回复"` 直接失败。而 Python 版用 `json.loads` 天然免疫。

修法要克制：我先试了 `printf '\u4e2d'`，结果 **dash 打印的是字面量，bash 才解码**（busybox 也不认），所以不能依赖 shell 内建解码。最终方案是"检测到 `\u` 才解，解不动就原样返回"：

```sh
json_unescape() {
    case $1 in
        *'\u'*) ;;
        *) printf '%s' "$1"; return 0 ;;
    esac
    if command -v python3 >/dev/null 2>&1; then
        printf '%s' "$1" | python3 -c '...'  # 有 python3 就解，没有就不解
    else
        printf '%s' "$1"
    fi
}
```

这样 shell 版的"零 Python 依赖"依然成立（没 Python 也能跑，只是中文回复显示成转义），有 Python 时显示更漂亮——**降级路径不能变成失败路径**。

**其三，argparse 的 `-c` 会被子命令覆盖。** 我先给主 parser 加了 `-c/--config`，又给每个子 parser 加了一遍，结果 `llm_probe.py -c foo showkey` 里 `-c` 的值被子 parser 的默认值悄悄顶掉。修法是给公共选项建一个 `parents=[common]`，并把默认值设成 `argparse.SUPPRESS`，让"没传"的子命令不去覆盖父级已经解析到的值。

## 五、密钥：加密后存进 env 文件

明文 key 躺在源码里是这次要解决的第二个问题。方案要满足三条：**配置文件能直接提交/分享**、**两个实现都能读**、**不引第三方依赖**。

### 密文格式

```
LLM_API_KEY_ENC=enc:v1:U2FsdGVkX18cDExvyVvz0vznzyJDRNNWRZUC+5kVACQ4nl7mB0ureTjb8+fhiCfdY1hqyNZGIwEYee0w6gB0Z4HFVBRUk1rLYIwBdjgtXNU=
```

解剖一下：

- `enc:v1:` 是自描述前缀，读到它就知道"这是密文，需要口令"，不是普通字符串。
- 后面 base64 解开是 `b"Salted__" + salt(8) + 密文`——这正是 `openssl enc -salt` 的原生输出格式。`U2FsdGVkX18` 就是 `Salted__` 的 base64，肉眼可辨。
- 参数固定为 `AES-256-CBC` + `PBKDF2-HMAC-SHA256` + **300000 轮迭代** + 8 字节随机 salt，key 和 IV 由 PBKDF2 一次派生出 48 字节（前 32 做 key，后 16 做 IV）。

关键在于：**Python 端不自己发明格式**，它产出的字节必须让 openssl CLI 能直接解开；shell 端则干脆整个调 openssl。于是互通变成天然的：

```sh
# shell 端解密（python 写的密文）
printf '%s' "${1#enc:v1:}" \
    | openssl base64 -d -A \
    | openssl enc -d -aes-256-cbc -pbkdf2 -iter 300000 -md sha256 -pass env:LLM_PASSPHRASE
```

Python 端优先用 `cryptography` 模块（有就用，避免起子进程），没有就回落到同样的 openssl 命令行；两条路径都用 `hashlib.pbkdf2_hmac` 严格按同一组参数派生，实测两边互写互读全通，错误口令两边都稳定拒绝（退出码 1）。

顺带一提，`-pass env:LLM_PASSPHRASE` 而不是 `-k "$PWD"`：**口令不进命令行参数**，否则 `ps` 一眼就能看到。

还有个坑在参数本身：`-pbkdf2` 是 **OpenSSL 1.1.1（2018）** 才加的选项，LibreSSL 没有它（而 LibreSSL 的版本号长得像 3.x，读版本号会误判）。所以两个实现都做**功能探测**——真跑一次 `-pbkdf2` 加密，成功才算支持——不支持就直接给出"需要 OpenSSL ≥ 1.1.1，或改用 `llm_probe.py` + `cryptography`"的可读报错，而不是让用户对着一屏 `Unknown option -pbkdf2` 发懵。

### 口令从哪来

口令**永远不写进配置文件**（写了等于没加密），也不进命令行参数。三个来源各有一块泄露面，先看表再选：

| 来源 | 泄露面 | 适用场景 |
|---|---|---|
| `LLM_PASSPHRASE_FILE` 指向的口令文件（`chmod 600`） | 只有文件权限 | **非交互 / CI 首选** |
| 终端交互输入（`getpass` / `stty -echo`） | 只在内存里过一遍 | **最安全** |
| 环境变量 `LLM_PASSPHRASE` | 会被**每个子进程继承** | 权宜之计（读到即摘） |
| `--passphrase` 参数 | **shell 历史 + `ps` 进程列表** | 仅临时测试（会打警告） |

第三行值得展开：环境变量不只是"同用户进程可读"（`/proc/<pid>/environ`）的问题，它会被原样传给**每一个**子进程——curl、openssl、openai SDK 自己拉起来的进程，全都拿到一份。所以两个实现的读取函数都做了同一件事：**读到就从自己环境里摘掉**。

```python
if os.environ.get("LLM_PASSPHRASE"):
    value = os.environ["LLM_PASSPHRASE"]
    scrub_env("LLM_PASSPHRASE")   # 读到就摘：后面再没有子进程继承得到
    return value
```

```sh
PASSPHRASE=$LLM_PASSPHRASE
unset LLM_PASSPHRASE              # 同上；openssl 用 VAR=val cmd 只喂那一条命令
```

同理，`setkey` 不再要求 `--key`：非交互时**从 stdin 读**（`printf '%s' "$KEY" | ... setkey`），密钥既不进 argv 也不进历史；真用了 `--key` / `--passphrase`，两个实现都会在 stderr 打一行警告。

拿不到口令时的行为要分情况：`--only net` 这种不需要密钥的探测**直接跳过解析**，不该被口令卡住；全量探测则明确报 `配置里是加密密钥，但拿不到解密口令` 并退出 1——**宁可拒绝，也不能默默降级成匿名请求然后给出"key 无效"的错误结论**。

### 配置文件不是脚本

这条是我坚持的：两个实现都**自己解析** `KEY=VALUE`，绝不用 `source` / `.` 加载配置。

```sh
cfg_get() {   # 用 sed 取值，不用 source
    sed -n "s/^[[:space:]]*$1[[:space:]]*=[[:space:]]*//p" "$CONFIG" | tail -n 1
}
```

原因很直白：`source` 一份配置等于执行任意命令。配置文件里写一行 `LLM_MODEL=$(rm -rf ~)` 或者 `$(touch /tmp/pwned)`，`source` 版本会照做，我们的版本只会把它当成字符串值。测试第 10 组专门验证了这一点（配置里埋 `$(touch ...)`，断言文件没被创建）。

配置文件由 `init` 生成、权限自动设为 600，格式见附录 C。

### 顺手把旧账清了

这次动手的直接起因，是仓库里躺着这么一个文件（`test_pekpik.py`，权限还是 664，组内可读）：

```python
client = OpenAI(base_url="https://aiapiv2.pekpik.com/v1",
                api_key="sk-KjDK********j43s")   # 明文硬编码（此处打码）
```

这把 key 已经失效并被轮换，**该文件也一并删除了**——它的探测能力是 `llm_probe probe --sdk` 的子集，留着只会变成第二份要同步维护的代码。密钥改由 `.llm_probe.env` 加密保存：51 字节明文 → 115 字符密文，任何脚本里都不再出现明文。

## 六、只想要一个最简 demo

分层探测是排障工具，不是入门材料。如果你只是想**先跑通一次调用**、看看端点到底能不能用，那 974 行的 `llm_probe.py` 显得太重了——所以仓库里另放了一个 `demo_minimal.py`，97 行、只有两个函数和一个入口，只做一件事：发一条消息，打印回复。

核心调用就这么几行：

```python
key = os.environ.get("LLM_API_KEY") or decrypt_secret(cfg["LLM_API_KEY_ENC"], passphrase)

client = OpenAI(base_url="https://api.openai.com/v1", api_key=key, timeout=30)
resp = client.chat.completions.create(
    model="gpt-4o-mini",
    messages=[{"role": "user", "content": "你好，请用一句话介绍你自己。"}],
)
print(resp.choices[0].message.content)
```

完整文件如下（同一份代码也在 `demo_minimal.py` 里，可直接 `python3 demo_minimal.py` 跑）：

```python
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
```
它和 `llm_probe` 的分工很清楚：

| | `demo_minimal.py` | `llm_probe.py probe` |
|---|---|---|
| 目的 | 演示**怎么调用** | 诊断**哪里不通** |
| 输出 | 只有回复文本 | 分层报告 + 结论 + 退出码 |
| 失败时 | 三档粗分类（2/3/4） | 六档（0–5），能区分 400/404/429/5xx |
| 依赖 | openai SDK | 零第三方依赖（`--sdk` 才需要） |
| 体量 | 97 行 | 974 行 / 851 行 |

**demo 跑通了不等于端点健康，demo 挂了也说不清原因**——所以它只是入口，结论仍以 `probe` 的退出码为准。反过来，`probe` 已经告诉你端点可用之后，真正在你的应用里要写的代码，就是上面那五行。

> 这个 demo 是 `test_pekpik.py` 的替代品：那个旧文件把 key 明文写死在脚本里，功能上又是 `probe --sdk` 的子集，已经删除。

## 七、两个实现怎么保持行为一致

"同一份配置、同一种密文、同一套退出码"是设计约束，不是事后补齐的。落到具体：

| 维度 | 做法 |
|---|---|
| 配置 | 都读 `.llm_probe.env`，都是自己解析、都不执行 |
| 优先级 | 都是 `命令行 > 环境变量 > 配置文件` |
| 密文 | 都是 `enc:v1:` + openssl 原生 `Salted__` 格式，PBKDF2 300000 轮 |
| 退出码 | 0/1/2/3/4/5 语义完全相同 |
| 分层 | 都是 L1/L2/L3，都是"L2 判死就跳过 L3，`--all` 强制" |
| 404 语义 | 都把 `/models` 的 404 标成非致命 |
| `--json` | 字段集合一致（含 `config`），`L3 推理` 恒带 `skipped` |

差异只有两处，且都写在明面上：shell 版**没有 L4 SDK 层**（`--only sdk` 会提示改用 py 版），以及 `\uXXXX` 解码依赖 python3（可选增强）。

一致性靠测试钉住：同一组 mock 场景跑两遍，**退出码、每个步骤的 `ok`/`skipped`、结论文字、JSON 字段集合逐项比对**，密文互写互读各测一次。**"应该是一样的"不算数，跑过才算。**

## 八、真实端点排障实录

拿真实中转站跑一遍，报告长这样（py 版）：

```text
[OK  ] L1 网络 [1/3]  DNS+TCP+TLS aiapiv2.pekpik.com:443 OK (153.3ms) TLSv1.3 CN=pekpik.com 有效期至 Nov 21 17:25:02 2026 GMT
[FAIL] L2 认证 [2/3]  HTTP 403：密钥无效
[SKIP] L3 推理 [3/3]  L2 认证未通过，已跳过（--all 可强制执行）
结论 ❌ 认证失败：API Key 无效或已过期（HTTP 403：密钥无效）
退出码 3
```

三个值得记下来的观察：

1. **L1 能过，说明问题与网络无关**——证书有效到 2026-11-21，TLS 1.3 握手 153ms。这一步直接排除了"是不是我网不好"这个最常见的自我怀疑。
2. **同一个 key，curl 报 401 无效的令牌，Python 报 403 密钥无效**。服务端对不同客户端的响应不完全一致（大概率是网关多节点或 UA 分流），但**两个状态码在判定里都归到 `kind=auth`，结论和退出码一致**——这正是"按语义分类而不是按字面匹配"的好处。
3. **`remote_ip` 是 `198.18.0.173`**，落在 `198.18.0.0/15` 这个 Clash/fake-ip 常用段，说明流量走了 TUN。这也解释了测试中偶发的 `SSL_read: unexpected eof`：不是目标站的问题，是本地代理链路抖动。L1 把 IP 打出来，这类"看起来像服务端炸了其实是本地代理"的情况一眼就能分开。

最终结论：这个端点**网络通、key 失效**，需要去后台重新生成 key——一次定位，没有猜。

## 九、可以怎么改

- **并发探测**：现在三层串行，加 `ThreadPoolExecutor` 或后台子 shell 可以把总耗时压到最慢的一层。
- **多 key / 多端点矩阵**：批量验证一组 `(base_url, model, key)`，输出表格。
- **把 401/403 的服务端原文存档**：`error.message` 里往往有 `request id`，拿去找服务商对账很有用（现在只截前 160 字符打印）。
- **接入 CI**：`llm_probe.py probe --json` 的结果可以做成健康检查，退出码非 0 就告警。
- **换加密算法**：想上 AES-GCM 或者 chacha20-poly1305 的话，记得同时改两个实现，或者干脆让 shell 端直接调用一个共享的 openssl 参数串。
- **`set -e`（已否决，别再"修"回去了）**：shell 版只用 `set -u` 是刻意的。本工具的核心是**抓住 curl 的非零退出码来分类故障**，`set -e` 会在第一个失败的 `err=$(curl ...)` 处直接中止：端口不通时实测 0 行输出、只剩 curl 的原始退出码 7，期望的"退出码 2 + 12 行分层报告"整个消失；健康端点虽然能跑，一遇网络故障就静默死。关键命令的状态都在脚本里显式判断，由 `tests/run_tests.sh` 兜底。

## 总结

- **"连不上"是四个问题叠在一起**：网络、key、模型/路径、SDK 兼容。分层探测的价值在于每层一个独立请求、一个独立判定，失败理由精确到"该改哪一行"。
- **退出码是主要接口**，人看报告、脚本看 `$?`，两者共用同一套结论。
- **404 要区分语义**：`/models` 404 是"这站不支持枚举"（非致命），`/chat/completions` 404 是"路径写错了"（致命）。
- **密钥加密的核心不是算法，是格式对齐**：让 Python 和 openssl 产出同一种字节，互通就是免费的；口令单独保管、配置文件永远不被 `source`。
- **测试要造自己的对照组**：mock 服务把 15 组分支跑干净，才敢说"这 44 项都对"；也才有机会抓到子 shell 丢赋值、`\uXXXX` 转义、argparse 覆盖这三个不跑就发现不了的 bug。

---

## 附录：完整源码

### A. `llm_probe.py`（974 行，Python 3.7+，零第三方依赖）

```python
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
    cfg = parse_env_file(config_path)
    if getattr(args, "key", None):
        warn_secret_arg("--key")
        key = args.key
    else:
        key = os.environ.get("LLM_API_KEY")
        if key:
            scrub_env("LLM_API_KEY")   # 读到就摘：别让它跟着子进程走
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
    probe.add_argument("--key", metavar="KEY",
                       help="临时指定密钥（不读配置；会留在 shell 历史和 ps 进程列表里，仅测试用）")
    probe.add_argument("--passphrase", metavar="PWD",
                       help="解密口令（同上；推荐 LLM_PASSPHRASE_FILE 口令文件或交互输入）")
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
```
### B. `llm_probe.sh`（851 行，POSIX sh，依赖 curl + openssl，OpenSSL ≥ 1.1.1）

```bash
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

VERSION="1.0"
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
TMP_DIR=""
PASSPHRASE=""

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
}
trap cleanup EXIT INT TERM HUP QUIT

# 临时响应体集中放在一个私有目录里（umask 077 → 0700），退出即删。
# 注意：kill -9 / SIGKILL 不触发 trap，目录会残留；下次运行是新建目录，不会
# 复用旧的。彻底清理: rm -rf "${TMPDIR:-/tmp}"/llm_probe.*
init_tmpdir() {
    umask 077
    TMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/llm_probe.XXXXXX") || die "mktemp -d 失败：无法创建临时目录"
    BODY_FILE="$TMP_DIR/response.json"
    ERR_FILE="$TMP_DIR/curl.err"
    : > "$BODY_FILE"
    : > "$ERR_FILE"
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
  --direct          不走系统代理（绕过 http_proxy/https_proxy）
  --json            JSON 输出

密钥选项:
  setkey            交互输入密钥（推荐）
  printf '%s' "$K" | setkey     非交互：从 stdin 读，不进 argv / 历史
  setkey --key K    直接给密钥（会留在 shell 历史和 ps 进程列表里）
  setkey/showkey --passphrase P  口令直接给（同上；推荐口令文件或交互）

退出码:
  0 全部通过   1 用法/配置错误   2 网络不通   3 认证失败   4 推理失败

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
    case $1 in
        '"'"'"*) printf '%s' "$1" | sed 's/^"//; s/"$//' ;;
        "'"*)    printf '%s' "$1" | sed "s/^'//; s/'\$//" ;;
        *)       printf '%s' "$1" ;;
    esac
}

load_config() {
    [ -f "$CONFIG" ] || return 0
    # 环境变量优先，配置文件只兜底（和 llm_probe.py 的优先级一致）
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
    TIMEOUT="${LLM_TIMEOUT:-$(strip_quotes "$(cfg_get LLM_TIMEOUT)")}"
    PROMPT="${LLM_PROMPT:-$(strip_quotes "$(cfg_get LLM_PROMPT)")}"
    MAX_TOKENS="${LLM_MAX_TOKENS:-$(strip_quotes "$(cfg_get LLM_MAX_TOKENS)")}"
    PASSPHRASE_FILE="${LLM_PASSPHRASE_FILE:-$(strip_quotes "$(cfg_get LLM_PASSPHRASE_FILE)")}"
    API_KEY_ENC="${LLM_API_KEY_ENC:-$(cfg_get LLM_API_KEY_ENC)}"
    API_KEY_PLAIN="${LLM_API_KEY:-$(cfg_get LLM_API_KEY)}"

    [ -n "$TIMEOUT" ] || TIMEOUT=30
    [ -n "$PROMPT" ] || PROMPT="你好"
    [ -n "$MAX_TOKENS" ] || MAX_TOKENS=64
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

probe_auth() {  # L2: GET /models
    STEP2_RAN=1
    opts=$(curl_common "$TIMEOUT")
    # shellcheck disable=SC2086
    set -- $opts
    if [ -n "$KEY" ]; then
        out=$(curl "$@" -H "Authorization: Bearer $KEY" -H "Accept: application/json" \
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
        auth_header="Authorization: Bearer $KEY"
        out=$(curl "$@" -H "$auth_header" -H "Content-Type: application/json" \
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
            STEP3_OK=1; STEP3_KIND=""
            STEP3_DETAIL="HTTP 200 (${ms}ms)"
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
    printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e 's/	/\\t/g'
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

ms_of() {  # 秒 → 毫秒（一位小数）
    awk -v s="$1" 'BEGIN{printf "%.1f", s*1000}'
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
        printf '  "config": "%s",\n' "$(json_escape "$CONFIG")"
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
    if [ -z "$new_key" ]; then
        if [ -n "${LLM_API_KEY:-}" ]; then
            new_key=$LLM_API_KEY
            unset LLM_API_KEY        # 读到就摘：别让它跟着子进程走
        elif [ -t 0 ]; then
            printf 'API Key: ' >&2
            stty -echo 2>/dev/null || true
            read -r new_key
            stty echo 2>/dev/null || true
            printf '\n' >&2
        else
            # 非交互：优先从 stdin 读（管道内容不进 argv、不进 shell 历史）
            if IFS= read -r new_key; then
                new_key=$(printf '%s' "$new_key" | head -n 1)
            else
                new_key=""
            fi
            [ -n "$new_key" ] || die "拿不到密钥。非交互环境建议从管道读:
  printf '%s' \"\$KEY\" | $PROG setkey
（或用 LLM_API_KEY 环境变量；--key 会留在 shell 历史和 ps 进程列表里）"
        fi
    fi
    [ -n "$new_key" ] || die "密钥为空"
    PASSPHRASE_FILE="${LLM_PASSPHRASE_FILE:-$(strip_quotes "$(cfg_get LLM_PASSPHRASE_FILE)")}"
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
        PASSPHRASE_FILE="${LLM_PASSPHRASE_FILE:-$(strip_quotes "$(cfg_get LLM_PASSPHRASE_FILE)")}"
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
    if [ -n "$API_KEY_ENC" ]; then
        PASSPHRASE_FILE="${LLM_PASSPHRASE_FILE:-$(strip_quotes "$(cfg_get LLM_PASSPHRASE_FILE)")}"
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

    case $CMD in
        probe)   run_probe ;;
        init)    do_init ;;
        setkey)  do_setkey ;;
        showkey) do_showkey ;;
        env)     do_env ;;
    esac
}

main "$@"
```
### C. 配置文件模板 `llm_probe.env.example`（37 行）

```bash
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
```
### D. `demo_minimal.py`（97 行，最简 demo）

```python
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
```
> 测试用的 mock 服务（`tests/mock_llm.py`，6 种模式：`ok / unauthorized / badpath / badmodel / ratelimit / noreduce`）和分支测试脚本（`tests/run_tests.sh`，15 组场景、44 项断言；另有 `tests/test_units.py` 单元测试）随代码一起放在 `~/Workspace/VibeCoding/llm-probe/tests/`，直接 `./tests/run_tests.sh` 即可复现第四节的全部结论（期望 `PASS=44 FAIL=0`，单元测试用 `python3 tests/test_units.py`）。测试刻意不读取真实配置的解密口令：前 8 组用 `--key` 显式传密钥，密文互通那组用临时配置配自己的口令。
