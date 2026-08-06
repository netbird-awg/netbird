# NetBird 本地 Integrations（OpenLDAP）二开 PRD

> 文档状态：Implemented / 验收收口中
> 目标版本：Local Integrations v1
> 优先级：P0 出站访问安全与 Connector 隔离加密，P1 页面入口与状态展示，P2 LDAP 单向同步
> 适用仓库：NetBird Management 与独立 `dashboard/` 仓库
> 核心约束：不引入 Redis；格式化、安全扫描、测试和构建全部在容器中执行；尽量减少与上游 `main` 的冲突

## 1. 背景

当前 Dashboard 的 `/integrations` 页面已经展示以下官方集成：

- Identity Provider Sync：Google Workspace、Microsoft Azure/Entra、Okta、SCIM。
- Event Streaming：Datadog、Amazon S3、Firehose、Generic HTTP。
- MDM & EDR：CrowdStrike、Intune、SentinelOne、Huntress、FleetDM。
- NetBird Cloud 下的 Single Sign-On。

这些页面会请求 `/api/integrations/*`，但当前开源 Management HTTP 路由没有提供对应业务处理器。仅解除 Dashboard 的许可遮罩不能获得完整集成能力。

本地二开已经具备 OpenLDAP Connector 配置、LDAP 用户创建、密码修改、MFA、LDAP 组选择和默认加入 `netbird` LDAP 组等能力，但配置入口位于 `Settings > Identity Providers`，没有在 `/integrations` 页面形成统一入口，也没有 LDAP 到 NetBird 的后台目录同步能力。

本 PRD 将 OpenLDAP 作为第一个本地集成，先复用现有认证配置，再增量实现可审计、可预览、可恢复的单向同步。

## 2. 状态图例

| 标记 | 含义 |
| --- | --- |
| `DONE` | 当前代码已经具备，开发时应复用 |
| `VERIFIED` | 已实现并通过容器化自动测试或构建验证 |
| `TODO-P0` | 安全阻断项，必须在页面入口上线前完成 |
| `TODO-P1` | v1 必须完成 |
| `TODO-P2` | 第二阶段完成，不阻塞只读入口上线 |
| `DEFERRED` | 已识别但不纳入当前排期，也不作为本期发布门禁 |
| `OUT` | 本 PRD 不实现 |

## 3. 产品目标

### 3.1 目标

1. 在 `/integrations?tab=identity-provider` 中增加不受企业许可遮罩影响的本地 OpenLDAP 入口。
2. 复用 `/api/identity-providers` 作为 OpenLDAP 连接配置的唯一事实来源，不复制 Connector 配置模型。
3. 提供安全的“测试连接”能力，区分网络、TLS、Bind、用户搜索和组搜索错误。
4. 第二阶段实现 OpenLDAP 到 NetBird 的单向用户和组映射同步。
5. 使用 PostgreSQL 保存同步配置、任务、运行记录和对象映射；不依赖 Redis。
6. 将本地代码集中在独立模块，上游文件只保留少量挂载点。

### 3.2 非目标

- `OUT` 不复制或绕过 NetBird 企业版 IdP Sync、EDR、Event Streaming 后端。
- `OUT` 不实现 NetBird 到 LDAP 的全量反向同步。
- `OUT` 不由同步任务创建、修改或删除 LDAP 目录对象。
- `OUT` 不在 v1 实现 Google、Azure、Okta、SCIM、EDR 等第三方集成。
- `OUT` 不新增 Redis、消息队列或独立调度组件。
- `OUT` 不改变 Main 的 Dex 原生 MFA 流程。

## 4. 现有能力基线

| 能力 | 状态 | 复用方式 |
| --- | --- | --- |
| Embedded Dex 身份提供商管理 | `DONE` | 继续使用现有 Embedded IdP Manager |
| `/api/identity-providers` CRUD | `DONE` | OpenLDAP 卡片读取该接口 |
| OpenLDAP Connector 表单 | `DONE` | 继续使用 `LDAPIdentityProviderForm.tsx` |
| LDAP 用户创建、删除、改密 | `DONE` | 不在 Integrations 页面重复实现 |
| LDAP 用户默认加入 `netbird` LDAP 组 | `DONE` | 同步范围默认也使用该组 |
| 用户首次登录强制改密 | `DONE` | 保持当前用户安全策略 |
| Main Dex 原生 MFA 与用户级策略 | `DONE` | 同步用户默认使用 `inherit` |
| LDAP/OIDC Connector 密钥应用层加密 | `VERIFIED` | 动态 Connector 配置整体加密落盘，配置文件与环境变量仍由部署层保护 |
| OIDC/HTTP 出站请求 SSRF 防护 | `VERIFIED` | HTTPS、地址分类、allowlist、重定向重验和 DNS pinning |
| Integrations OpenLDAP 卡片 | `VERIFIED` | 独立本地组件，官方许可区域只增加一个挂载点 |
| LDAP 连接诊断 | `VERIFIED` | 分阶段 test endpoint，总时限 15 秒 |
| LDAP 用户/组预览与同步 | `VERIFIED` | PostgreSQL 队列、Preview、Run、保护阈值和运行记录 |

## 5. 用户与权限

### 5.1 用户角色

| 角色 | 查看状态 | 测试连接 | 修改 Connector | 配置同步 | 手动同步 | 查看运行记录 |
| --- | --- | --- | --- | --- | --- | --- |
| Owner | 是 | 是 | 是 | 是 | 是 | 是 |
| Admin | 是 | 是 | 是 | 是 | 是 | 是 |
| Network Admin | 由 `identity_providers` 权限决定 | 由 Update 权限决定 | 由现有权限决定 | 由 Update 权限决定 | 由 Update 权限决定 | 是 |
| Auditor | 是 | 否 | 否 | 否 | 否 | 是 |
| 普通用户 | 否 | 否 | 否 | 否 | 否 | 否 |

### 5.2 权限规则

- 页面和 API 都必须执行服务端权限校验；Dashboard 隐藏按钮不能作为安全边界。
- P1 复用现有 `identity_providers` Read/Create/Update/Delete 权限。
- P2 v1 明确复用 `identity_providers` Read/Update 权限，避免修改上游权限模块；不得依赖 `settings.read` 作为写权限。
- 测试连接、预览和手动同步按写操作处理，必须记录发起用户。
- 子账户请求必须继续经过现有 child-account 校验。

## 6. 用户流程

### 6.1 未配置 OpenLDAP

1. 管理员进入 `/integrations?tab=identity-provider`。
2. 页面在企业版功能提示和许可遮罩之外展示 `OpenLDAP Authentication` 卡片。
3. 状态显示 `Not configured`，主按钮显示 `Configure`。
4. 点击后进入 `/settings?tab=identity-providers`。
5. 管理员创建并保存 `LDAP / OpenLDAP` Connector。
6. 保存后可立即执行连接测试；测试失败不会删除 Connector，但必须返回可定位的阶段错误。
7. 返回 Integrations 页面后卡片显示 `Configured`。

### 6.2 已配置 OpenLDAP

1. 卡片显示 Connector 名称、数量和 TLS 模式。
2. 主按钮显示 `Manage`，跳转到现有 Identity Providers 页面。
3. P2 启用后额外显示同步状态、最近成功时间、下次执行时间和最近一次变更统计。
4. 多个 LDAP Connector 时显示 `N connectors`，进入管理页后选择具体 Connector。

### 6.3 开启目录同步

1. 管理员选择一个 LDAP Connector。
2. Base DN、LDAP Filter 和属性映射继续由 Connector 统一管理，同步模块不复制这些字段。
3. 配置独立的 `sync_scope_groups`；默认包含 LDAP `netbird` 组，且 UI 默认选中。
4. 配置 LDAP 组到 NetBird Auto Groups 的映射。
5. 执行 `Preview`，展示新增、更新、禁用、跳过和冲突数量及有限样例。
6. 管理员确认后保存并启用。
7. 系统立即创建一次异步同步任务，并按配置周期继续执行。

### 6.4 同步失败

1. 单次同步进入 `failed` 或 `partial` 状态，保留结构化错误摘要。
2. 已成功提交的对象不得因页面刷新重复创建。
3. 系统按退避策略重试网络类错误，不自动重试配置和权限错误。
4. 连续失败达到阈值后暂停自动同步并在卡片显示 `Needs attention`。
5. 管理员修复配置并测试成功后可恢复同步。

## 7. Dashboard 需求

### 7.1 页面结构（`VERIFIED`）

本地组件实际结构：

```text
dashboard/src/modules/local-integrations/
├── LocalIdentityProviderIntegrations.tsx
└── openldap/
    ├── OpenLDAPIntegrationCard.tsx
    ├── OpenLDAPStatus.tsx
    ├── OpenLDAPSyncModal.tsx
    └── useOpenLDAPIntegration.ts
```

官方 `IdentityProviderTab.tsx` 只允许增加一个导入和一个组件挂载点。建议布局：

```text
Identity Provider Sync
├── Local integrations
│   └── OpenLDAP Authentication
└── Official licensed integrations
    └── 原有 LockedFeatureInfoCard + LockedFeatureOverlay
```

### 7.2 卡片字段

| 字段 | 未配置 | 已配置 | 同步启用后 |
| --- | --- | --- | --- |
| 名称 | OpenLDAP Authentication | Connector 名称 | Connector 名称 |
| 状态 | Not configured | Configured | Syncing / Healthy / Failed / Paused |
| 说明 | Authenticate users with OpenLDAP | TLS 模式、Connector 数量 | 最近成功时间、变更统计 |
| 主按钮 | Configure | Manage | View sync |
| 次按钮 | 无 | Test connection | Sync now |

### 7.3 交互要求

- 不删除、不移动、不重写官方集成卡片。
- 不修改企业许可判断；本地卡片放在许可遮罩之外。
- 当前用户只有 Read 权限时，显示状态但禁用配置、测试和同步按钮。
- 所有异步操作显示 loading、成功和失败通知，并显示服务端 `requestId`。
- 不在浏览器 localStorage 保存 LDAP 密码、Bind DN、Token 或完整配置。
- API 返回的密码字段必须为空或固定掩码；掩码值不得再次作为新密码提交。
- 响应式布局至少覆盖 1280px、1024px、768px 和 375px。
- 键盘可访问；状态不能只依赖颜色表达。

## 8. Management API 需求

### 8.1 P1：复用接口

继续使用：

- `GET /api/identity-providers`
- `POST /api/identity-providers`
- `PUT /api/identity-providers/{idpId}`
- `DELETE /api/identity-providers/{idpId}`
- `GET /api/identity-providers/{idpId}/ldap-groups`

新增：

#### `POST /api/identity-providers/{idpId}/test`

用途：测试已保存 Connector。请求体为空，不接收密码。

```json
{
  "status": "ok",
  "checks": {
    "dns": "ok",
    "tcp": "ok",
    "tls": "ok",
    "bind": "ok",
    "user_search": "ok",
    "group_search": "ok"
  },
  "latency_ms": 42,
  "tested_at": "2026-07-16T10:00:00Z"
}
```

规则：

- 每个阶段设置独立超时，总时间不超过 15 秒。
- 错误响应返回稳定错误码，不返回 Bind 密码、完整 DN 查询结果或服务端堆栈。
- 同一用户和 Connector 每分钟最多执行 5 次。
- 记录 `identityprovider.test` 审计事件。

### 8.2 P2：同步接口

统一命名空间：`/api/local/integrations/ldap-sync`。

| 方法 | 路径 | 用途 |
| --- | --- | --- |
| GET | `/` | 列出本账户同步配置和状态 |
| GET | `/{connectorId}` | 获取指定配置，永不返回密钥 |
| PUT | `/{connectorId}` | 创建或更新同步配置 |
| POST | `/{connectorId}/preview` | 计算差异但不写入 |
| POST | `/{connectorId}/runs` | 创建手动同步任务，返回 202 |
| GET | `/{connectorId}/runs` | 分页查询运行记录 |
| GET | `/{connectorId}/runs/{runId}` | 查询单次运行详情 |
| POST | `/{connectorId}/runs/{runId}/confirm` | 确认超过禁用阈值的任务 |
| POST | `/{connectorId}/runs/{runId}/cancel` | 取消 queued / awaiting_approval 任务 |
| POST | `/{connectorId}/pause` | 暂停自动同步 |
| POST | `/{connectorId}/resume` | 测试成功后恢复同步 |

配置示例：

```json
{
  "enabled": true,
  "interval_minutes": 60,
  "sync_scope_groups": ["netbird"],
  "group_mappings": [
    {
      "ldap_group": "netbird",
      "netbird_auto_group_ids": ["group-id"]
    }
  ],
  "deprovision_action": "disable",
  "conflict_policy": "skip"
}
```

约束：

- `interval_minutes` 最小 5，最大 1440。
- `sync_scope_groups` 默认且至少包含 `netbird`；若确需关闭，必须通过显式高级设置确认。
- `deprovision_action` v1 只允许 `disable` 或 `ignore`，默认 `disable`；不支持自动删除。
- `conflict_policy` v1 只允许 `skip`，不得覆盖手工创建的同邮箱用户。
- 手动同步同一 Connector 同时最多一个运行中任务，重复请求返回 `409 sync_already_running`。
- Preview 最大读取 5000 用户和 1000 组；超限返回明确错误，不静默截断后执行。

## 9. 同步语义

### 9.1 数据方向

```text
OpenLDAP ──读取──> Local LDAP Sync ──写入──> NetBird PostgreSQL
```

- LDAP 是身份与 LDAP 组成员关系的来源。
- NetBird `User.AutoGroups` 是新设备自动加入 NetBird Peer Groups 的配置，不能与 LDAP 目录组混淆。
- 同步任务不写回 LDAP；管理员从 NetBird 页面主动创建 LDAP 用户的现有流程保持不变。

### 9.2 用户匹配

按以下顺序匹配：

1. `connector_id + LDAP stable ID` 的本地映射。
2. 可解码的 Dex 用户 ID 与 Connector ID。
3. 规范化邮箱，仅用于发现冲突，不用于自动接管已有用户。

LDAP stable ID 优先使用配置的 ID Attribute。缺失稳定 ID、邮箱或邮箱格式无效的对象进入 `skipped`，不得创建用户。

### 9.3 用户写入

- 新用户角色固定为 `user`，同步不得授予 Owner、Admin 或 Network Admin。
- 新用户 `Issued=integration`，并设置本地 Integration Reference。
- 默认 `MFAPolicy=inherit`，MFA 最终是否必需继续由现有账户级和用户级策略决定。
- LDAP `netbird` 组用于同步范围；NetBird Auto Groups 只来自管理员确认的映射。
- 姓名、邮箱变更仅更新由同一 Connector 管理的用户。
- LDAP 对象离开同步范围时，默认将 NetBird 用户设为 blocked/disabled，不删除设备、审计记录和历史运行数据。

### 9.4 组映射

- LDAP 组名不能直接当作 NetBird Group ID 使用。
- v1 管理员只能把 LDAP 组映射到当前账户已有的 NetBird Auto Group；服务端校验 Group ID 和账户归属。
- `OUT-v1` 不由同步任务自动创建 NetBird Group，避免目录命名错误直接扩散为策略对象；后续若增加，必须单独设计稳定 ID、重命名和删除语义。
- 删除映射只移除该集成管理的 Auto Group 关系，不修改管理员手工添加的关系。

### 9.5 幂等性与事务

- 每个 LDAP 对象生成内容指纹；指纹未变化时跳过写入。
- 单个用户及其映射在一个数据库事务中提交。
- 整次同步允许 `partial`，但必须记录成功、失败和跳过对象数量。
- 活跃运行唯一键为 `account_id + connector_id`；Preview/Run 另使用配置版本和源指纹绑定高风险确认。
- Worker 崩溃后，超过 lease 时间的 `running` 任务可被安全重新领取。

## 10. PostgreSQL 数据模型

### 10.1 `local_ldap_sync_configs`

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| id | bigint | 主键，也是 Integration Reference ID |
| account_id | varchar | 账户隔离键 |
| connector_id | varchar | Dex Connector ID，账户内唯一 |
| enabled | boolean | 是否自动同步 |
| interval_minutes | integer | 同步周期 |
| sync_scope_groups | jsonb | 独立同步范围，默认包含 `netbird` |
| group_mappings | jsonb | LDAP 组名到现有 NetBird Group ID 映射 |
| deprovision_action | varchar | disable / ignore |
| conflict_policy | varchar | v1 固定 skip |
| failure_count | integer | 连续失败次数 |
| paused_reason | varchar | 自动暂停原因 |
| next_run_at | timestamptz | 下次执行时间 |
| last_success_at | timestamptz | 最近成功时间 |
| revision | bigint | 乐观锁版本 |
| created_at / updated_at | timestamptz | 审计时间 |

唯一索引：`(account_id, connector_id)`。

### 10.2 `local_ldap_sync_runs`

保存运行状态、触发方式、发起用户、开始/结束时间、对象统计、错误码、有限错误摘要和 lease 信息。状态限定为：

```text
queued -> running -> success | partial | failed
queued -> cancelled
running -> awaiting_approval -> queued | cancelled
```

### 10.3 `local_ldap_sync_objects`

保存：

- `account_id`
- `connector_id`
- `object_type`：user / group
- `external_id`：使用 Connector 派生键计算的 LDAP stable ID HMAC-SHA-256，用于稳定匹配和唯一索引
- `netbird_object_id`
- `source_fingerprint`
- `last_seen_at`
- `managed_fields`
- `status`

唯一索引：`(account_id, connector_id, object_type, external_id)`。

### 10.4 调度与并发

- Management 内置 worker 每 30 秒查询到期配置。
- 使用 `FOR UPDATE SKIP LOCKED` 领取任务。
- 使用 PostgreSQL 部分唯一索引约束同一账户和 Connector 只能存在一个 `queued`、`awaiting_approval` 或 `running` 任务。
- 运行表承担任务队列和恢复点，不新增 Redis。
- 多副本 Management 必须产生与单副本一致的执行结果。

## 11. 安全需求

### 11.1 Connector 密钥存储（`VERIFIED`）

动态 Connector 配置在 Dex Storage 装饰层统一加密后落盘，运行时读取时解密。已有明文 Connector 在 Management 启动时完成就地迁移；密文带版本前缀，便于后续轮换和格式演进。

密钥加密边界确定如下：

- 部署配置文件、Docker Compose Secret 挂载文件和环境变量中的密钥不由应用层二次加密；由部署系统负责文件权限、Secret 注入和访问控制。
- 通过 Dashboard/API 动态创建并写入 Dex Storage 的 Connector 配置必须应用层加密。
- 加密覆盖完整动态 Connector 配置，因此包含 LDAP `bindPW`、OIDC `clientSecret` 及账户归属元数据。
- Create/Update/List/Get 全部经过同一存储装饰层；底层数据库只接触密文，Dex 运行时获得解密后的配置。
- 使用 Management 注入的 `DataStoreEncryptionKey`，采用带版本号和随机 nonce 的密文格式；未配置密钥时仅保持开发兼容，不得作为生产部署。

同时维持以下纵深防护措施：

- List/Get API 永不返回 LDAP `bindPW`、OIDC `clientSecret` 的明文或存储值，只返回 `secret_configured: true/false`。
- 更新时空密码表示“保留原密码”，不能把 `****` 写入数据库。
- Management、Dex 和 PostgreSQL 日志不得包含 Connector 密钥。
- PostgreSQL 使用独立最小权限账户，禁止业务外账户读取 Connector 表。
- 数据库磁盘、快照和备份必须启用基础设施层加密，并限制备份访问权限。
- Connector 密钥通过受控 Secret 管理流程定期轮换；人员离职或疑似泄露后立即轮换。
- 启动迁移或解密失败必须 fail closed，不得退回明文或忽略 Connector 错误。

### 11.2 出站访问与 SSRF（`VERIFIED`）

- OIDC discovery 默认只允许 HTTPS。
- 每次 DNS 解析和 HTTP 跳转后重新校验目标地址。
- 默认拒绝 loopback、link-local、multicast、云元数据地址和未授权 Unix/文件协议。
- 自托管环境访问内网 IdP 必须通过显式 allowlist，例如域名后缀或 CIDR；不得使用全局“关闭 SSRF 检查”。
- 禁止 URL 中携带用户名和密码。
- 限制响应体、响应时间、跳转次数和并发数。
- LDAP 允许访问配置的内网目录，但 Host 必须通过专用 LDAP 地址解析器，禁止 URL scheme 注入。

### 11.3 LDAP 安全

- 默认 LDAPS；Plain LDAP 必须显示高风险提示并要求显式确认。
- `insecure_skip_verify` 默认关闭，生产配置启用时持续显示警告。
- LDAP Filter 值、DN 组件和属性名分别使用正确的转义/白名单校验。
- 禁止管理员输入的属性名改变过滤器结构。
- Bind、搜索、分页均设置超时和结果上限。
- 不记录 Bind 密码、用户密码、Authorization Header、完整 LDAP 条目和 MFA Secret。

### 11.4 同步安全

- 所有查询强制带 `account_id`，跨账户对象 ID 返回 404。
- Preview 与 Run 使用相同的过滤器和权限逻辑。
- 同步永不提升用户角色。
- 删除/禁用操作设置单次保护阈值：影响超过 20% 或 100 个用户时自动暂停，要求人工确认。
- 审计事件至少包含配置变更、测试、预览、运行、暂停、恢复和高风险确认。
- 错误摘要进行敏感字段清洗，并限制长度。

## 12. 可观测性

### 12.1 指标（`VERIFIED`）

- `netbird_local_ldap_sync_runs_total{status}`
- `netbird_local_ldap_sync_duration_seconds`
- `netbird_local_ldap_sync_objects_total{type,result}`
- `netbird_local_ldap_sync_failures_total{stage,code}`
- `netbird_local_ldap_sync_queue_depth`
- `netbird_local_ldap_sync_last_success_timestamp`

标签不得包含邮箱、DN、Connector 密钥或 LDAP 用户 ID。

### 12.2 日志（`VERIFIED`）

- 同步 API 请求沿用 Management `request_id`；后台 worker 日志包含 `run_id`、`account_id`、`connector_id`。
- 用户对象只记录不可逆短哈希。
- 错误码稳定，便于 Dashboard 展示和告警聚合。

## 13. 代码边界与合并策略

### 13.1 Backend 实际结构

```text
management/server/localintegrations/
└── ldapsync/
    ├── flags.go
    ├── handler.go
    ├── manager.go
    ├── metrics.go
    ├── model/model.go
    ├── planner.go
    ├── token.go
    ├── worker.go

management/server/outbound/
└── validator.go
```

挂载点控制为：

- `management/internals/server/boot.go`：一个 endpoint 注册挂载点。
- `management/internals/server/modules.go`：一个 Service 构造函数。
- `management/internals/server/server.go`：一个 worker 启动挂载点。
- `shared/management/http/api/openapi.yml`：独立 API 段；生成文件只通过容器内生成流程更新。

### 13.2 Frontend 实际结构

所有本地页面组件放入 `dashboard/src/modules/local-integrations/`。官方 Integrations 文件只保留一个组件挂载点，不直接修改官方 Google、Azure、SCIM、EDR 或 Event Streaming 文件。

### 13.3 提交拆分

建议按以下顺序提交：

1. `security: validate identity provider outbound targets`
2. `api: add ldap connector test endpoint`
3. `dashboard: add local openldap integration card`
4. `storage: add local ldap sync models`
5. `server: add ldap sync preview and reconciler`
6. `server: add postgres-backed ldap sync worker`
7. `dashboard: add ldap sync configuration and run history`
8. `test: add openldap sync integration coverage`

每个提交必须能独立编译；P0 和 P1 不依赖 P2。

## 14. 测试方案

所有命令必须通过根目录 `Makefile` 的容器目标执行，不在宿主机安装或执行 Go、Node、npm、gofmt、gosec 等工具。

### 14.1 单元测试

- API 和日志永不返回 Connector 密钥，空密码更新不会覆盖已有密码。
- SSRF：loopback、私网、metadata、IPv6、DNS 重绑定、跳转目标、异常 scheme。
- LDAP Filter/DN/属性注入。
- 用户匹配、邮箱冲突、角色不提升、组映射和 managed-fields 合并。
- Preview 不写数据库。
- 同一输入重复同步无额外变更。
- 大批量禁用触发保护阈值。
- Worker lease、失败恢复和多副本并发领取。

### 14.2 集成测试

当前自动化 Docker Compose 测试栈实际启动：

- PostgreSQL 17
- OpenLDAP
- 只读挂载源码的 Go 测试容器

当前已覆盖：

1. PostgreSQL 数据模型迁移、配置乐观锁、运行与对象生命周期。
2. 同一账户和 Connector 活动任务唯一约束。
3. 两个并发 worker 仅有一个能领取同一任务。
4. queued / awaiting approval 任务的原子取消状态约束。
5. OpenLDAP DNS/TCP/Bind/用户搜索/组搜索诊断。
6. 有界目录读取和 `netbird` 默认同步范围。

发布前仍需补充完整环境测试矩阵：

1. LDAPS 成功、证书错误和 StartTLS。
2. 5000 用户分页与重复执行压力测试。
3. LDAP 新增、改名、改邮箱、离组和禁用的真实 Management 写入。
4. Management 重启、双实例长时间 lease 恢复和多账户隔离。
5. Management + Dashboard 浏览器 E2E。

### 14.3 Dashboard E2E

已在本地 OSS 自托管 HTTPS 环境完成：

- 单 Connector 下 OpenLDAP 卡片可见，官方许可遮罩行为不变。
- Configured、Syncing、Healthy 状态切换。
- 分阶段连接测试成功通知。
- 默认 `netbird` 范围、Plain LDAP 风险提示、Preview、启用、初次运行和手动运行。
- queued 到 success 的运行历史刷新。
- 375px、768px、1024px、1280px 下弹窗无水平溢出。
- 重复同步为 `0 create / 0 update / 0 disable / 0 conflict`，仅刷新已有对象映射。

仍需补充：

- 无 Connector 和多 Connector 状态。
- 只读权限账户的按钮与服务端拒绝矩阵。
- 高风险确认、取消、暂停和恢复的完整浏览器流程。
- 键盘焦点顺序和屏幕阅读器专项检查。

### 14.4 容器验证命令

开发过程中至少执行：

```bash
make dev-format GO_FILES="<本次修改的 Go 文件>"
make dev-test-fast
make dev-vet
make dev-security
make dev-mod-check
make dev-dashboard-format DASHBOARD_FILES="<本次修改的 Dashboard 文件>"
make dev-dashboard-check DASHBOARD_FILES="<本次修改的 Dashboard 文件>"
make dev-dashboard-security
make dev-dashboard-build
```

涉及 PostgreSQL/OpenLDAP 的集成测试已提供独立容器目标：

```bash
make dev-test-local-integrations
```

最终合并前执行：

```bash
make dev-verify
make dev-conflict-report
make dev-conflict-report-dashboard
```

## 15. 验收标准

### 15.1 P0 当前安全门禁

- [x] List/Get API 只返回 `secret_configured`，Connector 密钥不进入响应模型；已增加序列化防泄漏测试。
- [x] SSRF 测试覆盖 IPv4、IPv6、metadata、混合解析、跳转和 DNS 重绑定。
- [x] Plain LDAP 和跳过证书验证都有明确且持续的风险提示。
- [x] Connector 配置已应用层加密落盘，并覆盖历史明文迁移测试。

### 15.2 P1 页面入口

- [x] `/integrations?tab=identity-provider` 的 OSS 本地组件已实现 OpenLDAP 卡片挂载。
- [x] 官方卡片和许可判断未重写，仅增加一个本地组件挂载点。
- [x] 未配置、已配置和多 Connector 状态已实现，连接测试返回稳定失败阶段。
- [x] 卡片跳转复用现有 Identity Providers 页面。
- [x] 服务端复用 `identity_providers` 权限，Dashboard 按写权限禁用操作。
- [x] Dashboard 格式化、检查、高危阈值安全扫描和生产构建均已在容器中通过。
- [x] 真实 OSS HTTPS 部署已完成单 Connector 流程和 375px 至 1280px 无水平溢出验证。
- [ ] 无/多 Connector、只读权限和键盘可访问性矩阵待执行。

### 15.3 P2 目录同步

- [x] Preview 与 Run 共用 `buildPlan`，Preview 路径不调用写事务。
- [x] 新 LDAP 用户角色固定为 `user`，已有特权用户进入冲突而不被接管。
- [x] `netbird` 默认同步范围由服务端强制保留，移除需要显式高级确认。
- [x] managed-fields 合并测试确认 LDAP 映射不会覆盖管理员手工 Auto Groups。
- [x] 真实目录重复同步已验证第二次为 `0 create / 0 update / 0 disable / 0 conflict`。
- [x] 离开范围的用户仅执行 blocked/disabled，不自动删除。
- [x] 超过 20% 或 100 人触发保护阈值，确认 Token 绑定账户、Connector、配置版本和源指纹。
- [x] PostgreSQL 部分唯一索引和并发领取测试确保同一 Connector 不会被双 worker 同时领取。
- [x] PostgreSQL/OpenLDAP 集成测试已在容器中通过。
- [ ] LDAPS、5000 用户分页、Management 重启恢复与多账户完整 E2E 待补充。

## 16. 发布与回滚

### 16.1 发布顺序

1. 先发布支持 SSRF 防护和 Connector 连接测试的 Management。
2. 确认补偿措施生效且连接测试通过。
3. 发布仅包含 OpenLDAP 卡片的 Dashboard。
4. P2 数据表和 worker 先以 `enabled=false` 发布。
5. 仅对测试账户启用同步，观察至少两个完整周期。
6. 再逐账户启用。

### 16.2 Feature Flags（`VERIFIED`）

- Management：`NB_LOCAL_INTEGRATIONS_ENABLED`、`NB_LOCAL_LDAP_SYNC_ENABLED`。
- Dashboard 运行时配置：`NETBIRD_LOCAL_INTEGRATIONS_ENABLED`、`NETBIRD_LOCAL_LDAP_SYNC_ENABLED`。

Dashboard 通过容器启动时生成的实例配置读取，不仅依赖构建时环境变量；默认关闭，由本地部署脚本显式启用。

### 16.3 回滚

- 关闭 `NB_LOCAL_LDAP_SYNC_ENABLED` 后停止领取新任务，但允许运行中事务安全结束。
- 回滚 Dashboard 不影响现有 Identity Providers 配置。
- 回滚到不识别 `enc:v1` Connector 密文的旧版本前，必须先执行受控解密迁移；禁止直接降级读取现有 Dex 数据库。
- 禁止通过删除同步表完成回滚。

## 17. 风险与决策

| 风险 | 影响 | 处理 |
| --- | --- | --- |
| Connector 加密密钥丢失或错误降级导致配置不可读 | 高 | 备份 DataStoreEncryptionKey；降级前执行受控迁移；启动解密失败时 fail closed |
| OIDC/HTTP 出站请求可访问非预期地址 | 高 | 统一 SSRF 校验与 allowlist |
| LDAP 目录 schema 差异大 | 中 | 配置化属性、Preview、测试矩阵 |
| 邮箱与已有用户冲突 | 高 | 默认 skip，不自动接管 |
| 大批量离组造成用户禁用 | 高 | 20%/100 人保护阈值 |
| 多副本重复执行 | 中 | PostgreSQL lock、lease、幂等键 |
| 上游 Integrations 页面频繁变化 | 中 | 独立组件和单挂载点 |

本期技术决策已落地：

1. P2 v1 复用 `identity_providers` Read/Update 权限，不修改上游权限模块。
2. 内网 OIDC allowlist 使用 `NB_OUTBOUND_ALLOW_PRIVATE_CIDRS` 和 `NB_OUTBOUND_ALLOW_DOMAIN_SUFFIXES`，均为逗号分隔值；没有全局关闭开关。
3. LDAP stable ID 使用 Connector 的 `UserSearchIDAttr`，不同目录 schema 继续由 Connector 配置负责。
4. v1 保护阈值固定为超过活跃托管用户 20% 或绝对数量 100；不开放账户级调低或关闭。
5. 动态 Connector 配置应用层加密已完成；配置文件、环境变量和 Secret 挂载文件仍不纳入应用层二次加密范围。

## 18. 里程碑与工作量参考

| 里程碑 | 内容 | 状态 | 依赖 | 预估 |
| --- | --- | --- | --- | --- |
| M0 | P0 SSRF 防护和出站目标校验 | `VERIFIED` | 无 | 2-3 人日 |
| M1 | Test API、OpenLDAP 卡片、权限 | `VERIFIED`；只读/多 Connector E2E 待收口 | M0 | 3-4 人日 |
| M2 | PostgreSQL 模型、Preview、Reconciler | `VERIFIED` | M0 | 5-7 人日 |
| M3 | Worker、并发恢复、运行记录 | `VERIFIED` | M2 | 4-6 人日 |
| M4 | Dashboard 同步配置、历史、完整集成测试 | 功能已实现；完整 E2E 矩阵待收口 | M3 | 4-6 人日 |

预估仅用于排期，最终以 M0 技术验证和 OpenLDAP 测试 schema 为准。
