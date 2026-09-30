<h1 align="center">agent-ledger</h1>

<p align="center"><b>当一个 AI agent 把工作交给另一个 AI agent 时，是谁授权的？出了错，谁来负责？</b><br>
没有任何共享记录说明「哪个 agent 在谁的授权下做了什么」。这是一个账本问题 —— 所以这就是一个账本。</p>

<p align="center">
<code>pip install agent-ledger</code> &nbsp;·&nbsp; 零依赖 &nbsp;·&nbsp; 不需要 API key &nbsp;·&nbsp; Python 3.10+<br>
<sub><a href="README.md">English</a></sub>
</p>

```console
$ al demo

▎6. Settling up — receipts all the way down

program-coordinator    completed  $0.0200  rcpt_1790775390758_6314f873
   └─ legal-review           completed  $0.3500  rcpt_1790775390759_944db8e4
      └─ localization           completed  $0.1200  rcpt_1790775390760_38d127ec

  chain length      3 hops
  total cost        $0.4900
  violations        none
  answerable to     urn:principal:northwind.internal:dana
```

三个 agent，两个组织，回答了一个问题：**这项工作可以追溯到 Dana。**

`al demo` 完整地**离线**运行这一切 —— 不需要网络、不需要 API key、不需要账号。它走过的每一条代码路径都是真实的。

> **快速跳转：** [问题是什么](#问题是什么) · [看它跑起来](#看它跑起来) · [安装](#安装) ·
> [怎么用](#怎么用) · [它保证了什么](#它保证了什么) · [出问题了？](#出问题了) ·
> [它是怎么工作的](#它是怎么工作的) · [设计文档](docs/DESIGN.md) · [安全策略](SECURITY.md)

---

## 问题是什么

两个标准已经解决了容易的那一半。

**[ARD](https://github.com/ards-project/ard-spec)**（Agentic Resource Discovery，v0.91）规定了 agent 如何被描述、发布，以及如何在联邦注册表之间被检索 —— 背后是 Google、Microsoft、Hugging Face、AWS、Cisco、GitHub、Nvidia、Salesforce 和 Snowflake。
**[A2A](https://github.com/a2aproject/A2A)** 规定了它们如何通话。

然后 ARD 自己的集成示例，刻意停在了这一句：

> "The orchestrator now has both capabilities and can proceed to invoke them using their respective protocols."

规范就在这里交接了。而且 ARD 自己也这么说：认证是**被委托出去的**，信任评估与它的相关性评分**完全解耦**，协议包装器的请求格式**"有待进一步定义"**。

于是生态能**找到**一个 agent、能**调用**它，但产不出任何东西来说清：

- **是哪个 principal** 授权了这项工作，中间经过了哪些跳
- 每一跳被授予了**什么范围** —— 能力、预算、截止时间
- **是否有哪一跳越过了这个范围**
- 结果错了的时候，**谁来负责**

`agent-ledger` 就是缺失的那一层。它为了发现而**实现** ARD 而不是重新发明它，为了执行而说 A2A，并承担两者都敞开的那部分 —— 用标准，而不是和标准竞争。

## 看它跑起来

会记忆的路由。这里没有任何一条规则是人写下的 —— 是账本改变了答案：

```console
▎8. Routing that remembers

  Before — nobody has a history yet:
    Localization Agent           ███████████████··· 0.845
    TranslatePro (partner)       ██████████████···· 0.768
    BargainLLM                   ████████████······ 0.658

  After — the localisation agent overran its budget twice:
    TranslatePro (partner)       ██████████████···· 0.768  ─   reputation=0.50
    Localization Agent           ██████████████···· 0.753  ▼-0.092   reputation=0.13
    BargainLLM                   ████████████······ 0.658  ─   reputation=0.50

  No rule was written. The ledger did the ranking.
```

一个**超支预算**的 agent，比一个直接失败的 agent 被扣得更重 —— 因为失败你看得见，超支你看不见：工作报告了成功，同时越过了被授予的权限。那是治理违规，不是运气不好。

而拒绝会被记录下来，不会被吞掉 —— "为什么什么都没发生"同样是个审计问题：

```console
$ al verify --ledger grid.jsonl
OK: 7 receipt lines verified; 7 signed

$ al verify --ledger grid.jsonl --sign-key-env AL_KEY --require-signature
FAILED: 1 tampered (line 3 (rcpt_1790775390758_6314f873))
  tampered: line 3 (rcpt_1790775390758_6314f873)
```

## 安装

**尚未发布到 PyPI。** `0.1.0` 已经打了 tag，产物也能干净构建，但还没有上传 —— 所以今天 `pip install agent-ledger` 会报 *no matching distribution*。请从源码安装：

```bash
git clone https://github.com/yaoyuxiang-gnn/agent-ledger
cd agent-ledger
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
python -m pip install -e ".[dev]"
al demo
```

请用虚拟环境，不要装进系统解释器。`pip install -e .` 会把命令行脚本写进解释器的 `Scripts`/`bin`，而在 Windows 上，python.org 的默认安装目录属于 Administrator、普通用户不可写 —— pip 于是报出一个很费解的
`[WinError 2] The system cannot find the file specified: ...al.exe.deleteme`。那是"找不到文件"而不是"拒绝访问"，所以读起来像构建错误。用 venv 可以完全绕开。

发布之后的预期接口是：

```bash
pip install agent-ledger      # 零运行时依赖
uvx agent-ledger demo         # 或者不安装直接跑
```

**可选扩展。** 核心包**完全没有运行时依赖**。用 Ed25519 签名 —— 唯一一种第三方能验证、却无法伪造的方案 —— 需要一个库，所以它是 extra 而不是依赖：

```bash
pip install 'agent-ledger[sign]'   # cryptography，用于 Ed25519 回执
```

## 怎么用

### 作为库

```python
from agent_ledger import Grid, Task

grid = Grid(
    registries=["https://registry.example.com/api/v1/search"],
    domains=["partner.example.com"],          # 静态 /.well-known/ard.json
)

outcome = grid.dispatch(
    Task(
        intent="review the vendor data processing agreement",
        required_capabilities=["contract_review"],
        issued_by="urn:principal:acme.com:dana",
        budget_usd=0.50,
    )
)

if outcome.ok:
    print(outcome.delegation.delegate.display_name)
    print(outcome.receipt.digest())          # 对 canonical 回执取 sha256
else:
    print("refused:", outcome.reason)        # 拒绝是结果，不是异常
```

没有配置 `executor` 时，委派会被下达并以 `pending` 出回执，不会调用任何东西 —— `outcome.receipt` 就是那份下达回执。传入 executor 就能让同一个调用一路走到结算。

### 作为命令行

```bash
# 通过 ARD 发现
al find "review a contract" --registry https://registry.example.com/api/v1/search

# 下达工作，带预算上限和受治理的账本
al delegate "review the DPA" -c contract_review \
    --domain partner.example --budget 0.50 --ledger grid.jsonl

# 查看保管链
al audit --ledger grid.jsonl

# 重新校验每一行 digest、链式链接和签名
al verify --ledger grid.jsonl
```

`registry.example.com` 是占位符 —— 换成真实的 ARD 注册表，或者用 `--domain` 指向一个提供 `/.well-known/ard.json` 的域名。`al demo` 两者都不需要，所以从它开始最合适。

**全部八条命令：**

| 命令 | 作用 |
|---|---|
| `al demo` | 30 秒看完整个项目，离线，不需要密钥 |
| `al find` | 通过 ARD 发现 agent |
| `al delegate` | 把任务交给最合适且合规的 agent |
| `al audit` | 从账本中列出委派链 |
| `al verify` | 重新校验每一行 digest、链式链接和签名 |
| `al policy` | 显示内置的策略预设 |
| `al bundle` | 导出或验证一个已签名的回执包 |
| `al conform` | 按 ARD 检查一份 manifest、一个发布方或一个注册表 |

### 真实的 A2A 执行

项目自带一个 A2A executor。它会抓取 Agent Card，驱动 `SendMessage` / `SendStreamingMessage` / `GetTask` / `CancelTask`，并把发生的事情记录到回执上：

```python
from agent_ledger import A2AExecutor, BearerCredential, Grid

grid = Grid(
    registries=[...],
    executor=A2AExecutor(
        credential=BearerCredential(token, reference="spiffe://acme.com/agents/grid")
    ),
)
outcome = grid.dispatch(task)
print(outcome.receipt.execution.task_ref)        # 对方自己对这项工作的 id
print(outcome.receipt.execution.state)           # TASK_STATE_COMPLETED，原样记录
print(outcome.receipt.execution.credential_ref)  # 是引用，绝不是密钥本身
```

**有意思的那一半是状态映射。** A2A 有一些状态是本库没有对应物的，因为一个委派只有"未结"和"已结"两种。其中两个 ——
`TASK_STATE_INPUT_REQUIRED` 和 `TASK_STATE_AUTH_REQUIRED` —— 刻意映射成 `accepted` 且 `ok=True`：**在等负责人**的工作不是 delegate 的失败，把它报成失败等于为一个没人回答的问题去扣 agent 的声誉，同时释放掉一个**确实还占用着**的预算承诺。未知状态判失败，不判成功。

### 会说"不"、并且说清为什么的策略

```python
from agent_ledger import Policy

policy = Policy.ceilinged(budget=0.50, chain=2.00, depth=3)
policy = policy.with_(
    denied_publishers=frozenset({"cheapapi.io"}),
    allowed_publishers=frozenset({"acme.com", "partner.example"}),
)
grid = Grid(policy=policy, ledger=ledger)
```

预设：`Policy.open_grid()`、`Policy.ceilinged()`、`Policy.zero_trust()`。自定义规则就是作用于 `RuleContext` 的普通函数 —— 没有 DSL 要学，也不用 fork。

策略统计的是**承诺**，不只是已花。天真做法是判断 `spent > cap`，而它是错的：五个并发委派各自都在上限内，加起来可以远远超过。

### 把证据交给另一个组织

共享一个可变存储是错误答案，这个项目反对它的理由和反对共享 reputation feed 一样：它是一个中心运营方，也是一个审查面。两个组织真正需要的，是**互相出示各自都能验证的证据，而无需信任对方的存储**。

```bash
al bundle export --ledger grid.jsonl --ledger-id acme-prod --out work.json
# 把 work.json 发出去，并通过一条你已经信任的渠道把它的 head 也发出去。
al bundle verify work.json --keyring their-keys.json --expect-head sha256:...
```

一个 bundle 就是一段账本内容加一份 manifest —— 账本本来就是正确的序列化格式，所以不存在第二种格式可以漂移。验证跑的是**同一套**检查。

### 检查 ARD 一致性

```bash
al conform manifest ./.well-known/ard.json
al conform publisher partner.example
al conform registry https://registry.example.com/api/v1
al conform --official manifest ard.json     # PATH 上有官方 CLI 时驱动它
```

### 把它看成一条 trace

回执本来就带起始时间、状态，以及通过 `parent_receipt_id` 表达的、**恰好是 trace 需要的父子关系**。所以一条委派链**就是**一条 trace，不需要任何 instrumentation：

```python
from agent_ledger import ledger_to_otlp, post_otlp

post_otlp(ledger_to_otlp(grid.ledger, service_name="agent-grid"), "http://localhost:4318/v1/traces")
```

## 它保证了什么

四层，每层回答一个不同的问题。这张表是诚实的版本 —— 一个夸大了自己的安全声明，比没有声明更糟：

| 层 | 证明 | 不证明 |
|---|---|---|
| `digest` | 某一行**没有被编辑** | 任何关于"已经不存在的行"的事 |
| `prev` 链 | 某一行**没有被删除、重排或拼接进来** | 是谁写的 |
| 签名 | **某个密钥**写了这一行 | 这把密钥属于回执里声称的那个 principal |
| **pinned keyring** | 那把密钥属于**那个 principal** | 那个 principal 是你以为的那个人 |

<details>
<summary><b>这在实践中意味着什么 —— 以及它做不到的三件事</b></summary>

- **签名说的是密钥，keyring 说的是人。** 有 pinned keyring 时，用别人的名字出示一把有效密钥会被抓住 —— 签名完全正确，旁边的**声明**不是。没有 keyring 时，什么也抓不住。这不是缺陷，这就是 keyring 存在的理由，而且 `tests/test_keyring.py` 把它写成了断言而不是注释。
- **HMAC 无法被第三方验证。** 它是对称的，所以每个验证者同时是伪造者：它是**信任域之内**的证据，不是**组织之间**的证据。核心包仍然提供它，因为它不需要任何依赖。要第三方可验证请用 Ed25519（`pip install 'agent-ledger[sign]'`），公钥能验证而无法伪造。
- **尾部截断只能靠对外公布的 head 发现。** 一个被缩短的前缀本身就是一条完全自洽的链，文件内部没有任何东西能察觉。`al verify` 会打印 head；`--expect-head` 用来比对你之前公布过的那个。**公布这个动作本身就是修复。**
- **keyring 不回答的是**这个"密钥到 principal"的映射是怎么来的。今天它是一个由人写的文件。从 SPIFFE bundle endpoint、DID document 或企业 PKI 获取它，是下一步 —— 也是这个项目应该采纳既有标准、而不是自己定义任何东西的那一处。

</details>

给每一份回执签名 —— 密钥从环境变量读，**绝不走 `argv`**，因为 `argv` 里的值在 `ps` 里可见，还会落进 shell 历史：

```bash
export AL_KEY=...                     # 从你的密钥管理服务取
al delegate "review the DPA" -c contract_review --domain partner.example \
    --ledger grid.jsonl --ledger-id acme-prod \
    --sign-key-env AL_KEY --key-id acme-2026 --signer urn:principal:acme.com:grid

al verify --ledger grid.jsonl --ledger-id acme-prod \
    --sign-key-env AL_KEY --keyring trust.json --require-signature
al verify --ledger grid.jsonl --json | jq -r .chain_head   # 把这个公布出去
al verify --ledger grid.jsonl --expect-head sha256:...     # 之后再拿它来比对
```

## 出问题了？

**Windows 上 `pip install -e .` 报 `[WinError 2] ... al.exe.deleteme`。**
你装进了系统解释器。`C:\PythonXX\Scripts` 属于 Administrator，普通用户不可写，所以 pip 创建不了命令行脚本 —— 而它报的是"找不到文件"而不是"拒绝访问"，这就是它读起来像构建错误的原因。建一个 venv（见[安装](#安装)）再试。如果 `import agent_ledger` 能用而 `al` 命令不存在，就是同一个问题：包进了 `site-packages`，脚本没进去。

**`al find` 说 `no entries found`。**
示例里默认指向 `registry.example.com`，那是占位符，不解析。用 `--registry` 传一个真实注册表，或用 `--domain` 传一个提供 `/.well-known/ard.json` 的域名。`al demo` 两者都不需要。

**`al verify` 说 `no such ledger file`。**
路径打错以前会打印 `OK: 0 receipt lines verified` 并 exit 0 —— 那恰恰是操作员最不会去复核的失败模式。现在它会失败，这是刻意的。

**`al verify` 说 `checked against ledger identity 'agent-ledger/default-ledger'`。**
账本身份**刻意不存进文件**：存了就等于让伪造者自己填，而绑定它正是阻止回执被重放进另一个账本的东西。所以没被告知身份的验证者会对着错误的东西检查，同时看到"断链"和"坏签名" —— 读起来像数据损坏，而不是像缺了一个输入。用 `--ledger-id` 传入账本写入时使用的那个身份。

**`al verify` 在我确定已签名的账本上报告 `bad signatures`。**
同样的原因。另外检查 `--sign-key-env` 传对了没有，以及 `--key-id` 和写入时是否一致。

**`al verify` 通过了，但我从账本里删掉了一行。**
如果删的是**末尾**，而你没有公布过 head，那没有任何东西能察觉 —— 被缩短的前缀是一条完全自洽的链。这是写在文档里的限制，不是 bug。请公布 `chain_head` 并使用 `--expect-head`。

**`al bundle verify` 说某一行由不受信任的密钥签名。**
bundle 是别人出示给你的证据，所以 `--require-signature` 是默认值，而没有 `--keyring` 就什么都验证不了。如果你确实想接受一个未签名的 bundle，用 `--allow-unsigned` —— 但它就无法证明是谁写的。

**签名时写入 keyring 被拒绝，报 `cannot be distributed`。**
你在试图持久化一个 HMAC verifier。HMAC 的"公钥"**就是**密钥，写出去等于把一个验证产物变成所有拿到文件的人共享的签名能力。第三方要验证请用 Ed25519，或者把 HMAC 验证留在持有密钥的那个进程里。

**我的注册表搜索结果让 `al find` 崩了。**
不应该崩，如果崩了那就是值得报的 bug —— ARD §5.3.2 允许搜索结果省略 `url`，这一情况由 `TestLeanSearchResults` 覆盖。报的时候请附上你注册表的响应形状。

**还是卡住？** 开一个 [issue](https://github.com/yaoyuxiang-gnn/agent-ledger/issues)，附上 `al demo` 的输出、你的 Python 版本和操作系统。如果和路由有关，请附上 `grid.candidates(task)` 的候选列表 —— 那些信号存在的意义，就是让路由 bug 不必靠猜来诊断。

## 它是怎么工作的

```
┌──────────────────────────────────────────────────────────────┐
│  Principal  （一个人，或代表某人的一个 agent）                  │
└───────────────────────────┬──────────────────────────────────┘
                            │  Task(intent, capabilities, budget)
┌───────────────────────────▼──────────────────────────────────┐
│  agent-ledger                                         │
│                                                              │
│   match ──▶ decide ──▶ delegate ──▶ receipt ──▶ chain        │
│     │         │            │           │          │          │
│  reputation  policy     authority   digest    lineage        │
└───────────────────────────┬──────────────────────────────────┘
                            │
        ┌───────────────────┴───────────────────┐
        ▼                                       ▼
┌──────────────────┐                  ┌──────────────────┐
│  ARD             │                  │  A2A / MCP       │
│  发现             │                  │  执行             │
│  （实现，         │                  │  （在 Executor    │
│   不重新发明）     │                  │   协议之后）       │
└──────────────────┘                  └──────────────────┘
```

中间那个盒子就是这个项目。下面两个是已经存在的标准，本项目刻意不与它们竞争。

**回执是问责的单位。** 一行日志记录"发生了什么"。一份回执记录的是*它被授权了、被谁授权、在什么限制之内、以及如何结束* —— 而且它可以被校验：

```
Receipt
├─ delegation_id        这份回执结算的是哪个委派
├─ parent_receipt_id    ──▶ 上一跳（正是这个字段让它成为一条链）
├─ delegated_by         谁授权的
├─ delegate             谁接收的
├─ scope_digest         对所授予权限取 sha256
├─ budget_usd / cost_usd
├─ outcome              pending | accepted | completed | failed | revoked
├─ execution            远端 task id、远端状态、凭据引用
├─ signature / key_id   这一行是谁写的
└─ digest               对以上全部内容取 canonical 形式后的 sha256
```

三个值得知道的决定：

- **每个委派一个稳定身份。** 一个委派终生使用同一个 `receipt_id`；状态转换在同一 id 下追加新行。这正是让链能在**飞行途中**被重新拼出来、而不必等一切结算完毕的原因。
- **对 digest 签名，绝不对签名取 digest。** 签名存放在存储信封里、与 digest 平级，绝不放进被 digest 的 body 里 —— 否则所有已经写下的账本都会开始验证失败，而且没有任何版本标记能解释为什么。
- **成本按 delegate 记录，绝不上卷。** 一个再委派的父级不吸收子级的成本。曾经上卷过一次，结果三跳的链为实际花费 `$0.49` 的工作报告了 `$1.08`，每个父级看起来都超支了。

想要以上全部背后的推理，包括这个设计哪里是错的？
→ **[docs/DESIGN.md](docs/DESIGN.md)**。

## 状态

Alpha，并且对此诚实。**578 个测试**，`ruff` 干净，每次提交都跑一遍离线的 `al demo`。

**能用的：** 发现（ARD）、匹配、策略、委派、回执、链、验证、签名、bundle 交换、JSON-RPC 上的 A2A 执行（含流式与取消）、适配器、OTLP 导出、ARD 一致性检查。

**不能用、并且对此大声说出来的：**

- **keyring 的解析。** pinned keyring 能把一把密钥绑定到一个 principal。但**获取**这个映射 —— 从 SPIFFE bundle endpoint、DID document 或企业 PKI —— 还没有实现；今天它是一个由人写的文件。
- **适配器是有文档的字段映射，不是验证过的集成。** AGNTCY、ClawTeam、OpenClaw 各有自己演进的格式，它们的规范都没有 vendored 进来。每个适配器映射声明的字段名、报告显式的 confidence，并在自己的 `summary` 里写明这一点。把一个猜的名字换成观察到的名字，是**一处一行**的改动。
- **A2A 推送通知**和 **gRPC / `HTTP+JSON` 绑定**。`require_supported_binding` 会在调用任何东西**之前**把这个缺口指名道姓地说出来，而不是用错误的协议发一个请求出去。
- **bundle 交换有格式，没有传输。** bundle 在密码学上可验证；把它从一个组织送到另一个组织，仍然是一个靠人发邮件附文件的过程。
- **没有内置公开的 ARD 注册表。** `al demo` 跑的是一个模拟联邦。

**我们不做这些声明：** 本项目不取代 ARD 或 A2A；签名本身不证明作者身份；账本证明的东西不超过[它保证了什么](#它保证了什么)那张表所写的。

## 参与贡献

见 **[CONTRIBUTING.md](CONTRIBUTING.md)**。push 之前要跑的那一条命令：

```bash
python -m pytest && python -m agent_ledger.cli demo --no-color
```

测试不需要安装步骤 —— `tests/conftest.py` 会把 `src` 放进 `sys.path`，所以刚 clone 下来就能直接跑：

```bash
git clone https://github.com/yaoyuxiang-gnn/agent-ledger
cd agent-ledger
python -m pytest
```

CI 强制保证三条承诺：**零运行时依赖**（`dependencies` 必须保持为空）、**测试绝不碰网络**（一切都走 `Transport` 协议）、**demo 保持离线且不需要密钥**。

在动手探测之前值得先读 **[SECURITY.md](SECURITY.md)**：问责声明本身的缺陷**就是**安全问题，哪怕什么都没崩 —— 里面也列了已经写在文档里的已知限制，免得 issue 区被路线图早已预料到的报告填满。

## 许可证

Apache-2.0。见 [LICENSE](LICENSE)。

---

<sub>**关键词：** 可问责 AI agent · agent 委派 · agent 交接 · agent 发现 · ARD · Agentic Resource Discovery · A2A · Agent2Agent · 能力匹配 · 意图路由 · 多 agent 溯源 · 任务路由 · agent 注册表 · MCP · AI agent 治理 · 审计追踪 · SCITT</sub>
