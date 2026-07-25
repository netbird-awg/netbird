# NetBird 本地二开工作流

本仓库的 Go 主工程与 `dashboard/` 是两个独立 Git 仓库。开发时应分别检查差异，但统一通过根目录 `Makefile` 的 `dev-*` 目标执行格式化、测试、构建和安全扫描。

## 约束

- 不在宿主机安装 Go、Node.js、npm 包或安全扫描工具。
- 默认快速测试不启动 Redis、PostgreSQL 或 Testcontainers。
- 不挂载 Docker socket，避免测试容器反向修改宿主机 Docker 状态。
- Go module、Go build 和 Dashboard npm 依赖只保存在具名 Docker 卷。
- Dashboard 构建在临时容器目录 `/work` 中完成，不生成宿主机 `.next/`、`out/` 或 `node_modules/`。

## 常用命令

格式化指定 Go 文件：

```bash
make dev-format GO_FILES="management/internals/server/mfa_policy.go idp/dex/mfa_policy_storage.go idp/dex/ldap_directory.go"
```

执行不依赖外部服务的快速回归：

```bash
make dev-test-fast
make dev-vet
make dev-security
make dev-mod-check
```

修改 MFA 或认证并发状态后，额外执行竞态检查：

```bash
make dev-test-race
```

格式化并检查本次修改的 Dashboard 文件：

```bash
make dev-dashboard-format DASHBOARD_FILES="src/components/ui/UserDropdown.tsx src/app/(dashboard)/team/user/page.tsx"
make dev-dashboard-check DASHBOARD_FILES="src/components/ui/UserDropdown.tsx src/app/(dashboard)/team/user/page.tsx"
make dev-dashboard-security
```

在隔离目录完成 Dashboard 生产构建：

```bash
make dev-dashboard-build
```

执行完整的本地二开验证：

```bash
make dev-verify
```

清理开发缓存卷：

```bash
make dev-clean
```

## 降低 main 合并冲突

每次同步上游前先获取远端并运行只读冲突预检：

```bash
git fetch origin main
git -C dashboard fetch origin main
make dev-conflict-report
make dev-conflict-report-dashboard
```

报告同时显示当前直接重叠文件，以及最近 200 个上游提交中的高频修改文件。建议遵循以下边界：

- `main` 仅作为上游镜像；二开代码放在独立的 `custom/*` 分支，并按 MFA、LDAP、密码策略、Dashboard 分成小提交。
- 新能力优先新增独立文件或组件；上游文件只保留导入、路由注册和一行委托调用。
- `openapi.yml` 是 API 唯一来源，`types.gen.go` 只通过生成流程更新，不手工修补生成文件。
- 不为整份上游文件配置 `ours` 合并策略，这会静默吞掉安全修复和新功能。
- 可以在仓库级启用 `git rerere` 复用已确认的冲突解法，但每次仍需执行容器验证：`git config rerere.enabled true`。

当前二开代码优先放在以下低耦合扩展文件中：

- `management/server/*_ldap.go`、`*_password.go`、`*_external_idp.go`：控制面业务扩展；原有 manager 文件只保留委托调用。
- `management/server/idp/embedded_*.go`、`idp/dex/*_password.go`：Embedded IdP 和 Dex 扩展。
- `idp/dex/mfa_*.go`：只对 Dex 原生 MFA 增加用户策略、密钥加密和失败限流，不复制 TOTP 流程。
- `management/internals/server/mfa_policy.go`：将用户策略和现有 Management 数据库接入 Dex，不引入 Redis。
- `dashboard/src/modules/users/UserSecurity*.tsx`：用户安全设置与菜单入口。
- `dashboard/src/modules/users/DashboardSecurityGuards.tsx`：仅保留登录后的强制改密守卫；MFA 在 Dex 登录阶段完成。
- `dashboard/src/modules/settings/LDAPIdentityProviderForm.tsx`：LDAP 表单、校验和请求规范化；Modal 只负责通用编排。

合并上游时先处理少量“挂载点”提交，再应用独立扩展文件提交。这样即使上游改了页面、manager 或 handler，也能把冲突限制在导入、路由和单行调用处。

## MFA 路径

- 本地密码和 LDAP/OpenLDAP 用户都使用 Main 的 Dex 原生 TOTP 注册、验证与 MFA 会话。
- 用户字段 `mfa_policy` 支持 `inherit`、`required`、`disabled`。本地用户的 `inherit` 跟随账户级 `local_mfa_enabled`；LDAP 用户的 `inherit` 默认不强制，可用 `required` 单独开启。
- TOTP 密钥继续存放在 Dex `idp.db` 的用户身份记录中，并由 Management datastore encryption key 加密后落盘。
- 失败次数和锁定时间存放在现有 Management 用户表中；连续 5 次失败锁定 15 分钟，不依赖 Redis，重启和多副本场景下状态不会丢失。
- 不再提供 Management 层 `/users/{id}/mfa/*` API，也不在 Client 或 Dashboard 登录后重复校验 TOTP。

## LDAP 代码边界

- `idp/dex/connector.go`：Connector 生命周期及 OIDC/OAuth 配置。
- `idp/dex/ldap_config.go`：LDAP 配置结构、Dex 配置编码与解析。
- `idp/dex/ldap_directory.go`：LDAP 连接、用户、密码和组目录操作。
- 新建 LDAP 用户始终加入 `netbird` LDAP 组；Dashboard 默认选中并锁定该组。
- LDAP Connector 必须配置 Group Search Base DN。默认组或附加组分配失败时，服务端回滚刚创建的 LDAP 用户，避免目录与 NetBird 数据不一致。

新增 LDAP 能力时应放入对应边界，避免重新把目录操作堆回 `connector.go`。
