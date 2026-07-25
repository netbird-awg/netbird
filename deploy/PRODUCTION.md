# NetBird 本地二开单机生产部署

本目录只维护一条部署路径：`getting-started-local.sh` 生成唯一的
`docker-compose.yml`，使用本地源码构建 Management 与 Dashboard 镜像，运行
PostgreSQL、OpenLDAP 和 Traefik。生产模式不使用 Nginx、Redis、Quick Tunnel、
自签名公网证书或测试 LDAP 用户。

## 前置条件

- 服务器已安装 Docker Engine 与 Docker Compose v2。
- 域名的 A/AAAA 记录已解析到服务器；使用 Cloudflare 时必须设置为 DNS only。
- 防火墙放行 TCP 80、443 和 UDP 3478；PostgreSQL、LDAP 不对宿主机暴露端口。
- 服务器时间同步正常，并已准备数据库与 LDAP 卷的异机备份位置。

## 构建镜像

只构建镜像，不生成配置或启动服务：

```bash
NETBIRD_LOCAL_ACTION=build bash deploy/getting-started-local.sh
```

默认镜像格式如下；Management 和 Dashboard 分别使用各自 `origin/main` 的提交：

```text
netbird-local/netbird-server:main-<management-main前8位>
netbird-local/dashboard:main-<dashboard-main前8位>
```

生产构建默认拒绝包含未提交改动的源码树，确保镜像标签、源码提交标签和实际构建输入可审计。仅临时开发验证可显式设置 `NETBIRD_ALLOW_DIRTY_BUILD=true`；该模式会输出不可复现警告，不应推送到生产镜像仓库。

镜像同时写入实际源码 HEAD、main 基线与 dirty 状态 OCI 标签。生产发布前应把本地
二开变更提交到专用分支，使镜像能由提交精确复现。

## 生产部署

```bash
NETBIRD_DOMAIN=netbird.example.com \
NETBIRD_LETSENCRYPT_EMAIL=ops@example.com \
NETBIRD_BIND_IP=192.0.2.10 \
bash deploy/getting-started-local.sh
```

脚本默认 `NETBIRD_DEPLOYMENT_MODE=production`，会：

- 构建本地 Management/Dashboard 镜像；
- 生成随机密码和数据加密密钥，权限设为 `0600`；
- 使用 PostgreSQL 17 与启用 TLS 的 OpenLDAP；
- 使用 Traefik 文件提供器路由，不向 Traefik 挂载 Docker Socket；
- 通过 Let's Encrypt 申请和自动续期证书；
- 在容器内执行 HTTPS/OIDC 健康检查。

部署同时启用本地 Generic SCIM 后端。IdP 中配置的 SCIM Base URL 为
`https://<域名>/api/scim/v2`；Token 只在创建或轮换时完整显示。详细的同步、
安全和回滚语义见 [`../docs/LOCAL-SCIM.md`](../docs/LOCAL-SCIM.md)。

部署同时启用本地 Event Streaming 后端，支持 Generic HTTPS、Datadog、Amazon
S3 和 Amazon Data Firehose。配置与待投递事件使用应用层 AES-GCM 加密并保存到
PostgreSQL outbox；不依赖 Redis。Generic HTTPS 默认禁止内网、回环和链路本地
地址。确需发送到内网时，只能通过 `NB_OUTBOUND_ALLOW_PRIVATE_CIDRS` 或
`NB_OUTBOUND_ALLOW_DOMAIN_SUFFIXES` 显式配置最小范围的允许列表。

局域网临时测试必须显式使用开发模式：

```bash
NETBIRD_DEPLOYMENT_MODE=development \
NETBIRD_TLS_MODE=selfsigned \
NETBIRD_DOMAIN=netbird.lan.example.com \
NETBIRD_BIND_IP=192.168.1.20 \
NETBIRD_BOOTSTRAP_TEST_USERS=true \
bash deploy/getting-started-local.sh
```

## 运维命令

停止服务但保留配置、密钥和数据卷：

```bash
NETBIRD_LOCAL_ACTION=down bash deploy/getting-started-local.sh
```

查看状态（生成的密钥文件不得提交 Git）：

```bash
docker compose \
  --env-file deploy/runtime/secrets.env \
  -f deploy/docker-compose.yml ps
```

## 备份与恢复验收

数据库至少每日执行一次逻辑备份，并将产物复制到异机存储：

```bash
docker compose \
  --env-file deploy/runtime/secrets.env \
  -f deploy/docker-compose.yml \
  exec -T postgres sh -ec \
  'PGPASSWORD="$POSTGRES_PASSWORD" pg_dump -Fc -U "$POSTGRES_USER" "$POSTGRES_DB"' \
  > netbird-$(date +%Y%m%d-%H%M%S).dump
```

还必须备份以下内容：

- `deploy/runtime/secrets.env`；
- `deploy/runtime/ldap-tls/`；
- Docker 卷 `ldap_data`、`ldap_config`；
- Traefik ACME 卷 `traefik_letsencrypt`。

恢复演练必须在隔离服务器完成，确认 Dashboard 登录、OIDC discovery、LDAP 登录、
MFA、Peer 重连和策略下发均正常后，备份方案才算有效。

## 上线检查

- `docker compose config --quiet` 通过，所有服务健康。
- 浏览器证书链可信，HTTP 自动跳转 HTTPS。
- Management 与 Dashboard 页面的版本均为各自 `main-<8位提交>`。
- 容器标签中的实际源码提交与发布记录一致，`source-dirty=false`。
- LDAP 新用户默认加入 `netbird`，首次登录改密和 MFA 策略已验证。
- 失效/禁用 LDAP 用户的 Peer 会立即过期，策略与 Auto Group 已刷新。
- SCIM Token 轮换、用户/组推送、成员变更和禁用流程已验证。
- Event Streaming 凭据脱敏、测试事件投递、重试和服务重启续投已验证。
- 已验证数据库、LDAP 和密钥的异机备份及恢复。
