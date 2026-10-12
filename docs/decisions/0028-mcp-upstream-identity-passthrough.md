# ADR-0028：MCP 上游身份透传——网关注入可信调用者身份

- 日期：2026-10-12
- 状态：**Proposed（待所有者拍板）**——本文只做选项与代价留档，**拍板前不实现**。拍板后二选一收口：选择实施 → 本文转 Accepted 并按下节「建议实施顺序」立项；选择维持不传身份 → 本文转 Accepted，结论 = 维持现状 + 记录 §1.3 的归属校验缺口由 MCP 侧自行承担。
- 效力：**无**。Proposed 状态不修订任何产品决策。落地后本 ADR 是 [ADR-0013](0013-mcp-proxy-wiring-proposal.md) 的**加注而非取代**：ADR-0013 已把 MCP 入站定为白名单构造转发、且网关在该路径上已经替换 `Authorization`（`McpProxyController.java:385-388`），本 ADR 只是在同一构造点新增一个权威头。
- 关联：[ADR-0013](0013-mcp-proxy-wiring-proposal.md)（MCP 调用代理接线——本文的直接基线）、[ADR-0010](0010-consumer-api-key-billing.md)/[0011](0011-consumer-jwt-authentication.md)（消费者凭据，即本 ADR 的 principal 空间）、[ADR-0002](0002-transparent-proxy.md)（协议透明——边界讨论见 §7.1）、`docs/api-contract.md` §5.16（mcp-services）、`docs/decisions/0013-*.md:23,51`（网关不解析 args 正文的既有边界）。
- 触发事件：把外部 MCP 服务 **slurm-skill**（`git.miqroera.com/intership/slurm-skill`）接入本网关。该 MCP 已实现 `IDENTITY_MODE=agent` 身份接收端并 fail-closed（缺头即 401），正等网关注入；而其**作业归属校验**（调用者只能查阅/取消自己的作业）在网关侧无处安放（§1.3），没有可信 principal 就无法实现。

---

## 1. 现状

### 1.1 网关今天向上游 MCP 发什么头：只有 4 个，全是构造出来的

`McpProxyController.forward()`（`backend/gateway-app/src/main/java/com/miqroera/miqrokey/gateway/proxy/McpProxyController.java:370-389`）
把出站头**从零构造**，只有四个：

| 头 | 来源 |
|---|---|
| `Content-Type` | 入站（缺省 `application/json`） |
| `Accept` | 入站 |
| `Session-Id` | 入站**同名字面头** |
| `Authorization: Bearer <upstream bear>` | 服务配置的后端密钥，经 `JdbcCredentialInjector` 解密 |

三个入站端点（`:143` POST `/mcp`、`:197` GET `/sse`、`:237` POST `/message`）都汇聚到这两个调用点
（`:333`、`:355`）→ 同一个私有 `forward()`。**这是一个白名单构造，不是黑名单过滤**——
入站任何其他头（含伪造的 `X-...-Principal`）当前都无法到达上游。

> 交接纪律：**永远不要把这里改成"过滤入站头"的黑名单形态**。一旦改成黑名单，伪造身份头就会随
> 之变成可达，本 ADR 的整个信任模型随之失效。要在代码里落一条注释把这个不变量写死。
>
> 另有一处可对照的先例：LLM 数据面（`ProxyController.java:457-459`）走的是
> `HeaderFilters.filterInboundHeaders`，其中 `x-miqrokey-` / `x-miqro-` 前缀的入站头**一律剥离**
> （`HeaderFilters.java:80-84`）——即仓库已有一个"网关自用头命名空间、客户端不可伪造"的约定，
> 但**只作用于 LLM 路径，与 MCP 路径无关**。

### 1.2 MCP 侧的接收端已经就绪

slurm-skill 的 `src/identity.py` 已实现：

- `IDENTITY_MODE=agent` 时读 `X-Slurm-Principal-ID`（及可选 `X-Slurm-Agent-ID`），**缺头抛
  `IdentityResolutionError` → 401，fail-closed**；`IDENTITY_MODE=shared` 时忽略这些头，principal
  恒为 `shared-agent`。
- principal 与 request id 的字符集约束：`_SAFE_PRINCIPAL_ID = ^[A-Za-z0-9._:@/-]{1,128}$`、
  `_SAFE_REQUEST_ID = ^[A-Za-z0-9._:-]{1,128}$`——**不合规即 401，这是硬约束**。
- 每次工具调用落一条结构化审计事件，含 `principal / identity_mode / identity_source / request_id /
  operation / outcome / duration_ms`；函数参数与文件内容**刻意不记**。
- 客户端可传 `X-Request-ID`，缺省则自生成。

网关侧的 `gateway_request_id` 是 `UUID.randomUUID().toString()`
（`McpProxyController.java:166`，36 字符 `[0-9a-f-]`），**落在 `_SAFE_REQUEST_ID` 内**，可直接复用做两侧审计的外键。

### 1.3 为什么"不传身份"已经不够用

三句话的推理链：

1. **网关做不了调用级授权**。ADR-0013 明确工具判定只读 JSON-RPC 信封的 `method.name`、**不解析 args 正文**
   （`0013:23,51`）。因此 `cancel_slurm_job(job_id=X)` 里的 X 属不属于调用者，网关在架构上就看不见。
2. **只有 MCP 同时看得见 principal 与 job_id**——但 MCP 今天拿不到 principal。
3. 于是**作业归属校验无处安放**。具体到这个 MCP：它今天唯一的归属校验在 REST 面
   （`src/slurm_api.py:174-248` 的 `JobOwnerStore` + `_fallback_verify_owner`），**MCP 面没有**。
   客户端一旦改为经网关直连 MCP 而绕过 `slurm-api`，**任何持有 `mcp:call` 的消费者只要猜到 job_id
   就能查阅、取消他人的作业、下载他人的产物**。这是静默的权限回退——不报错，只少一道防线。

现状的代价汇总：MCP 的身份模式空转；逐操作审计只剩一个 `shared-agent` 无法归因；归属校验无法落地。

### 1.4 principal 空间：只有消费者，没有 Virtual Key

MCP 数据面的入站凭据只有消费者面（`mqk_api_` Key 或消费者 JWT，需 `mcp:call` 作用域，
`McpProxyController.java:158,556-579`）——ADR-0013 决策点 1 选项 B 的结论。Virtual Key 不解析出 consumer，
与本路径无关。**因此 principal 空间 = `api_consumers`**，不存在 vkey↔consumer 映射问题。

网关侧已经持有该身份：`mcp_access_log` 有 `consumer_id` / `consumer_name`
（`V29__mcp_access_log.sql:26-27`）。缺口不在"不知道是谁"，只在"没往下传"。

### 1.5 一个必须写在前面的前提：这不是 SLURM 层面的隔离

slurm-mcp 只持**一个** SLURM SSH 账号（多集群各一个）。所以 principal 透传买到的是：
**归因** + **MCP 侧自行维护的归属表**（principal → job_id），
**不是** SLURM 调度器层面的用户隔离。后者需要每用户凭证，超出本 ADR 范围（§7）。

---

## 2. 决策点 1：信任模型（本 ADR 的核心）

问题：网关注入的 `X-...-Principal-ID`，MCP 凭什么信？

| 选项 | 说明 | 评估 |
|---|---|---|
| **A. 不传身份**（现状） | 维持 `IDENTITY_MODE=shared` | 零成本，但 §1.3 的缺口永久存在；MCP 侧已写好的身份模式永远用不上 |
| **B. 明文注入 + 网络隔离** | 网关注入明文头；信任模型 = "只有网关能到达该 MCP 端点"（MCP 的 NodePort 收敛为仅内网 / 仅网关网段可达） | 实现最简（网关侧 +1 行构造，MCP 侧零改动）。**但把全部安全性押在部署上**：任何一次端口误暴露、同网段横向、或 K8s Service 被直连，即升级为"可冒充任意消费者"，且 MCP 侧无法自证 |
| **C. 签名注入**（推荐） | 网关注入明文头 + 对规范化字段做 MAC，MCP 侧验签并校验时窗 | 需要 MCP 侧小改（加验签）；但**即使 MCP 端点被直连也无法伪造身份**，且失败是显式 401 而非静默越权 |
| **D. mTLS 绑定通道** | 网关持客户端证书，MCP 侧校验 | 隔离最强；但要为 gateway 的 WebClient 配客户端证书、为 MCP 配信任链，且 principal 仍需另传（证书标识的是网关而非消费者）。相对 C 的增量价值低、工程量高 |

**推荐 C，并把 B 作为纵深防御而非替代**（签名 + 收敛端点可达性）。理由：B 单独用时，
"安全性 = 部署正确性"，而部署正确性恰恰是最容易在演示/内网环境被妥协的一环；
C 把判断权交回 MCP，且失败模式是显式的。

### 2.1 签名算法：HMAC-SHA256，而不是 Ed25519

先看**威胁模型**：谁能绕过网关直连 MCP？同集群横向、误暴露的 NodePort、运维误操作。
攻破方若进一步拿下 MCP 容器，则已经持有 **SLURM SSH 私钥**——不需要伪造身份就能以 slurm 账号作业。
因此 **"MCP 容器被攻破后仍不可伪造身份"这一条的增量价值，在这个威胁模型下很低**。

于是：

- **HMAC-SHA256（对称，每服务一把共享密钥）**：网关持钥签名，MCP 持同一把钥验签。
  Python 侧零新依赖（stdlib `hmac` / `hashlib`），Java 侧复用既有 `HmacVirtualKeyProvider`
  （`HmacSHA256`，`domain/crypto/impl/`）的形状。
- **Ed25519（非对称）**：网关持私钥、MCP 仅持公钥，MCP 被攻破也无法伪造。
  Java 侧有现成先例（`provider-adapters/.../catalog/CatalogSignatureVerifier.java` 用 JDK 内置 Ed25519），
  但 **Python 侧需要引入 `cryptography` 或 `PyNaCl`**——对一个由独立团队维护的仓库，
  这是要额外背的依赖与审批。

**推荐 HMAC-SHA256**：以 §2.1 的威胁模型，Ed25519 买到的东西少于它带来的跨仓依赖成本。
若 owner 认为"MCP 容器被攻破"必须纳入威胁模型，则改选 Ed25519，代价是 slurm-skill 侧新增一个 Python 依赖。

---

## 3. 决策点 2：principal 的取值与头名

### 3.1 取值

| 选项 | 评估 |
|---|---|
| **`consumer_id`（UUID 字符串）**（推荐） | 落进 `_SAFE_PRINCIPAL_ID`（36 字符、`[0-9a-f-]`）；稳定、不含 PII、可直接回联 `api_consumers` 与 `mcp_access_log.consumer_id` |
| `consumer_name` | 审计可读，但**调用方自选、可变**，且含中文时会被 `_SAFE_PRINCIPAL_ID` 拒绝（该正则是 ASCII 白名单） |
| 自行编号（如 `u42`） | 需要额外映射表；收益不明 |

**推荐 `consumer_id`**。可读性用**另一个头**解决（§3.3）：权威身份与展示名分开，展示名不参与任何授权判断。

### 3.2 头名：中立名 + 按服务别名

| 选项 | 评估 |
|---|---|
| 硬编码上游既有头名（如 `X-Slurm-Principal-ID`） | MCP 侧零改动；但把某一个上游的私有约定写进网关，每接一个新 MCP 都要改网关代码 |
| 网关中立名（`X-MiqroKey-Principal-Id`） | 网关干净；slurm-skill 需改一处常量（`identity.py` 的头名），改动极小 |
| **按服务可配头名**（推荐） | `mcp_services` 加一列（如 `identity_header_name`）；slurm 配成 `X-Slurm-Principal-ID`（MCP 零改动），未来的 MCP 配各自的约定 |

**推荐按服务可配**：一次小迁移换掉长期的每上游一改。同时**无论配成什么名字，网关都必须只在
白名单构造点写入**（§1.1 的不变量），不提供"透传客户端同名头"的模式。

### 3.3 展示名（可选子决策）

若 MCP 审计希望看到可读的调用者，可另注入一个**明确标注为展示用、不参与授权**的头
（如 `X-...-Principal-Name`）。取值建议 `consumer_name`，并在 MCP 侧仅落审计、绝不用于判定。
若不接受多一个头，此项可整体砍掉——**不影响本 ADR 的其他部分**。

---

## 4. 决策点 3：签名的覆盖面

规范化串（建议按此顺序拼接后做 MAC，分隔符用 `\n` 避免拼接歧义）：

```
<service_name>\n<principal_id>\n<rpc_method>\n<tool_name>\n<timestamp_epoch_seconds>\n<gateway_request_id>
```

| 字段 | 为什么签 | 成本 |
|---|---|---|
| `service_name` | 防跨服务重放（把 A 服务的签名挪到 B 服务） | 0 |
| `principal_id` | 核心 | 0 |
| `rpc_method` / `tool_name` | 防"把 `tools/call` 的签名挪到另一个工具上"。网关**已经解析出 toolName**（ADR-0013 既有能力），零额外成本 | 0 |
| `timestamp` | 时窗校验（防旧签名长期可用） | 0 |
| `gateway_request_id` | 两侧审计可 join；顺带让每次签名唯一 | 0 |

**刻意不签请求体**：签名会诱导"读正文"，与 ADR-0013「不解析 args 正文」的边界冲突，
且要在热路径上多算一次哈希。§4 的覆盖面对本文的威胁模型已经够用。

**刻意不加 nonce 缓存**：时窗内的重放要成立，攻击者必须能**截获**在途请求——
而这已被 TLS 覆盖。为把窗口内重放也堵死而引入跨副本 nonce 缓存（MCP 是 2 副本无状态部署），
是拿一个有状态组件换一个 TLS 已覆盖的场景，不值得。**残留风险写在这里：时窗内重放未被堵死。**

**时窗建议 ±60s**（与 NTP 偏差容忍度的常见取值）。MCP 侧对超出时窗的签名返回 401 并落审计。

---

## 5. 决策点 4：开关、默认值与上线顺序

- **默认关**。`mcp_services` 新增开关（如 `identity_forwarding` 枚举 `OFF | SIGNED`），默认 `OFF`；
  `OFF` 时网关不写任何身份头——完全保持今天的 4 头行为。与 ADR-0013 里 F12/F13「默认关闭挂点」
  的处理方式一致。
- **两端必须协同切换，且顺序不能反**。MCP 的 `agent` 模式是 fail-closed，
  顺序必须是：① 网关开注入（此时 MCP 仍是 `shared`，多出来的头被忽略，无害）
  → ② 确认头确实到达并验签通过 → ③ MCP 切 `IDENTITY_MODE=agent`。
  反序会得到一个 100% 401 的服务——这正是本 ADR 要避免的事故。
- **密钥来源**：复用 `miqrokey.crypto.encryption.versions` 的文件密钥加载与权限校验路径
  （`FileSecretProvider` 强制 0400、拒符号链接/全零），不新造一套密钥管理。
  密钥按服务一把（不进 `mcp_services` 明文列；参照 V38 `backend_auth_mode` 的密文写法）。
- **快照**：开关与头名必须进 `route-snapshot`（网关热路径不同步查控制面，CLAUDE.md §3）。
  密钥不进快照——它在网关侧，解密/签名在既有 `credentialDecryptScheduler` 上做。

---

## 6. 观测与验收口径

- 网关侧：`mcp_access_log` 既有 `consumer_id` / `consumer_name` / `gateway_request_id`
  （`V29__mcp_access_log.sql:26,34`）已经够用，**不需要新表**。
- MCP 侧：审计事件里的 `principal_id` 与 `request_id` 应与网关 `mcp_access_log` **按 request_id 一一对上**。
  这是本 ADR 最容易验证、也最该写进验收条件的一条。
- 验收建议（实施时细化）：同一消费者发起 N 次 `tools/call`，两侧行数相等、
  `principal_id == consumer_id`、`request_id` 相等；另跑一次**负例**——用错误密钥签名 / 篡改 principal
  后直连 MCP，必须 401 且落审计。

---

## 7. 边界：本 ADR 不解决什么

1. **不是取代 ADR-0002 的透明性，而是加注**。ADR-0002 约束的是 LLM 推理路径的正文透明
   （不得重排/改写 JSON）。MCP 是另一条路径，且该路径**已经**在做头级替换（网关替换 `Authorization`）。
   本 ADR 只在既有构造点新增一个头，不触碰任何请求体。
2. **不含作业归属校验的实现**。本 ADR 只交付"可信 principal 可被 MCP 看见"这一前置条件；
   归属表（principal → job_id）的建立与校验属于 MCP 侧的独立工作。
3. **不含 Streamable HTTP 会话语义**（`Mcp-Session-Id` 透传、`/mcp` 的 GET/DELETE）。正交问题，
   另案处理——但如果 MCP 是 stateful 会话，那件事会先挡住接入。
4. **不含配额与指标**。MCP 面目前不计配额（`QuotaMetric` 只有 `TOKENS|REQUESTS|COST`）、
   无 `aigw.mcp.*` 指标，与本 ADR 无关。
5. **不含按消费者限流**。`CLAUDE.md §2` 的「不限流」决策不变（相关评估见 ADR-0026）。
6. **不含 SLURM 调度器层面的用户隔离**（§1.5）。

---

## 8. 建议实施顺序（Accepted 后）

1. `mcp_services` 新迁移：`identity_forwarding` 开关 + `identity_header_name`（**追加迁移，不改 V20**，
   见 `CLAUDE.md §7`）+ 密钥密文列。
2. `route-snapshot` 带上这两个非密钥字段；密钥不进快照。
3. `McpProxyController.forward()`：在白名单构造点按服务配置写入身份头与签名
   （签名在 `credentialDecryptScheduler` 上做，**不得在 event loop 上做**——
   过 `GatewayNoBlockingTest`）。
4. 管理 API + `api-contract.md` §5.16 + OpenAPI 重生成（`check-openapi-breaking.py` 是 CI 门禁）。
5. 契约测试：伪造头不可达上游（负例）、`OFF` 时不写头、`SIGNED` 时两侧 request_id 对齐。
6. slurm-skill 侧：`identity.py` 加验签与时窗校验（HMAC 用 stdlib）；部署切 `IDENTITY_MODE=agent`。
7. 更新 `docs/decisions/0013-*.md` 的相关段落（加注、不取代）、`docs/security.md`、`docs/api-contract.md`。

## 9. 未决（需 owner/leader）

- 决策点 1：C（签名）还是 B（仅网络隔离）还是 D（mTLS）？——**这是本 ADR 唯一必须拍板才能动工的点**。
- 决策点 2：头名用"按服务可配"还是先硬编码 slurm 的头名（前者多一次迁移，后者多一次改网关）？
- 决策点 3：签名覆盖面是否接受"不含请求体摘要"（即接受"签名不绑定 args"这一残留）？
- 决策点 2.1：是否把"MCP 容器被攻破"纳入威胁模型？若是，改 HMAC 为 Ed25519 并接受 Python 侧新依赖。
- §3.3 展示名头：要不要（可整体砍掉）。
- 时窗取值（建议 ±60s）。
