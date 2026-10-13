# ADR-0030：普通用户的 MCP 调用凭据形态——每用户一个消费者

- 日期：2026-10-13
- 状态：**Accepted（2026-10-13）**——决策：普通用户的自助 MCP 凭据 = **每用户一个 API 消费者**，在 `api_consumers` 上**追加**一列归属用户；消费者 JWT 留二期。实施按 §6 立项。
- 效力：**生效**。本 ADR 解除 issue #1 备注里「需要拍板：普通用户的 MCP 凭据用什么形态」这一阻塞，并顺带定下 issue #13 中「谁有权用」的口径。**不改变** [ADR-0013](0013-mcp-proxy-wiring-proposal.md) 的数据面形态：调用者仍是消费者凭据，[ADR-0028](0028-mcp-upstream-identity-passthrough.md) 的 principal 仍是 `consumer_id`——本 ADR 只补上「消费者由谁拥有」。
- 关联：issue #1（面向桌面客户端的 MCP 消费者自助接入面）、issue #13（把服务登记进注册表）、[ADR-0013](0013-mcp-proxy-wiring-proposal.md)（消费者凭据通道与两级 ACL——本 ADR 的直接基线）、[ADR-0010](0010-consumer-api-key-billing.md)/[0011](0011-consumer-jwt-authentication.md)（消费者 Key / JWT 两套通道）、[ADR-0017](0017-platform-oidc-login.md)（平台 OIDC——二期 JWT 签发方的落点）、`docs/api-contract.md` §5.10（API 消费者）与 §5.16（mcp-services）。

---

## 1. 现状：消费者是匿名机器身份，与人没有绑定

`api_consumers`（V13）只有 `tenant_id`、`name`、`key_digest`、`key_prefix`、`status`；后续迁移加过 `jwt_public_key_pem` 等（V14）、`capabilities`（V37）、`expires_at`（V39），**从未加过归属用户的列**（已逐条核对 `db/migration/` 下的全部相关迁移）。

而 MCP 的访问控制是按**消费者**建的：`mcp_service_access.mode`（V25）+ `mcp_access_grants`（`consumer_id` 可带 `tool_id`）。因此：

- **"这个用户能调用哪些 MCP 服务"目前无法计算**——ACL 的键是消费者，而消费者不指向任何用户。
- `/api/v1/me/*` 下**没有任何 MCP 端点**：接入地址只在管理面（`GET /api/v1/admin/mcp-services/{id}/connection`），凭据只由管理员签发（`POST /api/v1/admin/api-consumers`，明文只出现一次）。
- 这正是 issue #1 的备注所指的待拍板项，也是它**第一步（自助发现）**就卡住的原因：发现列表要求「口径与 ACL 一致」，而口径的输入缺了。

> 注意：`capabilities`（V37）与 `expires_at`（V39）**已经存在**，所以「裁作用域」「设到期」这两件事不需要新机制——本 ADR 只补归属关系。

## 2. 决策

**每用户一个 API 消费者**，并在 `api_consumers` 上追加归属列（新迁移，**不改 V13**；`(tenant_id, user_id)` 唯一，允许为空以兼容既有的机器消费者）。

用户侧只暴露**自己的**那一个消费者：

- 首次访问自助端点时按需创建（或由管理员预建），凭据明文仍**只显示一次**；
- 支持**自助轮换**（换一把新 Key，旧的立即失效）与在**到期**前重取；
- 用户只能看到/操作归属自己的消费者，管理面不受影响。

## 3. 为什么是它

- **复用现成的消费者通道**：鉴权（`mqk_api_` Key 或 JWT）、服务级/工具级 ACL、`mcp_access_log` 归因、吊销、到期——**全部现成**，本 ADR 只补一列。
- **它直接解决 ACL 口径问题**：`mcp_service_access` 本就按消费者授权，「用户能看到哪些服务」退化成「我那个消费者被授权了哪些」，`GET /api/v1/me/mcp-services` 的实现是一次查询，且与 ACL 天然一致（无权的不出现）。
- **满足 issue #1 的硬约束**：「桌面端不应持有长期**共享**密钥」——每用户一把不是共享的；再叠加到期与即时吊销。
- **与 ADR-0028 正交**：身份透传的 principal 仍是 `consumer_id`，本 ADR 不改变它，只是让那个 id 有主。

## 4. 被否的选项

- **Virtual Key 通道**：[ADR-0013](0013-mcp-proxy-wiring-proposal.md) 决策点 1 已以「Virtual Key 无消费者身份」排除过；重开需要 ACL 侧配套改造。而且 Virtual Key 的语义是「一 Key 绑定一个项目、一个供应商产品和一个真实凭证」，与「调 MCP」不是同一件事——把它复用成 MCP 凭据会让那个绑定语义变形。
- **消费者 JWT 作为一期（即 [ADR-0011](0011-consumer-jwt-authentication.md) 那条通道）**：对桌面端**其实更优**（短时令牌、端上不留长期密钥、失效更快），但**缺一个签发方**——桌面端登录的是平台（Qraft），不是网关，网关侧尚无「用平台会话换取网关令牌」的路径。那是 [ADR-0017](0017-platform-oidc-login.md) 平台 OIDC 那条线的延伸，**放二期**。
  **二期切换时 ACL 侧不用动**（仍按消费者授权），所以一期选消费者 Key 不会成为二期 JWT 的债。

## 5. 影响

- **issue #1**：阻塞解除。自助发现与自助凭据都能落地；验收标准里「列表口径与 ACL 一致」「吊销后失效」都变成可测。
- **issue #13**：登记服务后，「谁有权用」有了答案——把用户自己的消费者放进服务/工具 ACL 即可。
- **管理面**：`POST /api/v1/admin/api-consumers` 与既有机器消费者的用法**不受影响**（归属列为空即旧的机器消费者）。
- **安全**：归属列让「某把 Key 属于谁」可查，这一点会同时改善吊销与审计的归因；但**不改变**凭据一旦泄露即可用的性质——到期与轮换仍是主要缓解。

## 6. 建议实施顺序（Accepted 后）

1. 追加迁移：`api_consumers` 加归属列（含 `(tenant_id, user_id)` 唯一约束，允许空）。
2. 用户自助端点（`/api/v1/me/mcp-services` 等）：列表按自己的消费者过滤 ACL；凭据领取/轮换；`api-contract.md` §5.10/§5.16 同步更新，并重生 OpenAPI baseline（CI 有破坏性检查）。
3. 把「用户 → 自己的消费者」的解析做成单一入口（后续 ADR-0028 的 principal 映射、配额按用户维度、用量视图都要用它），避免各处重复推导。
4. 二期（另开 ADR）：平台会话 → 短期网关令牌，替换凭据形态；ACL 侧不动。
