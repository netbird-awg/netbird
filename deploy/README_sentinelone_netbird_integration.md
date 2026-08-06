生产部署由唯一的 `docker-compose.yml` 管理。请先通过部署脚本生成并启动：

```bash
bash getting-started-local.sh
```

需要强制无缓存重建时：

```bash
NETBIRD_BUILD_NO_CACHE=true bash getting-started-local.sh
```


# SentinelOne + NetBird 集成脚本说明

本文档说明如何使用 `deploy/sentinelone_netbird_integration.py` 实现 SentinelOne 与 NetBird 的联动。

## 1. 脚本能做什么

脚本支持 3 种模式：

- `configure`：调用 NetBird EDR SentinelOne 接口，创建或更新集成配置。
- `audit`：在后端接口不可用时，执行轻量审计（仅输出风险，不做封禁）。
- `enforce`：基于 SentinelOne 指标计算安全分数，低于阈值时封禁 NetBird 用户登录。

## 2. 前置条件

- Python 3.9+（建议 3.10+）
- 可以访问：
  - NetBird 管理地址（例如 `https://netbird.example.com`）
  - SentinelOne 管理 API 地址（例如 `https://usea1-partners.sentinelone.net`）
- 拥有以下凭据：
  - `NETBIRD_TOKEN`（NetBird API Token）
  - `S1_API_TOKEN`（SentinelOne API Token）

## 3. 如何获取 `NETBIRD_TOKEN`

推荐：创建 Service User，再为该用户生成 Personal Access Token（PAT）。

### 方式 A：Dashboard 生成 PAT

1. 使用管理员登录 NetBird Dashboard。
2. 进入个人设置中的 Personal Access Tokens。
3. 创建 Token（名称、过期时间）。
4. 复制生成的 token（仅显示一次）。

### 方式 B：API 方式（自动化推荐）

1. 先创建 service user（如果尚未创建）。
2. 调用 `POST /api/users/{userId}/tokens` 创建 token。
3. 返回结果中的 `plain_token` 即可作为 `NETBIRD_TOKEN`。

> 建议使用最小权限账号；生产环境避免使用个人账号长期 token。

## 4. 评分与封禁逻辑（`enforce`）

SentinelOne 无单一原生安全分数字段，脚本采用复合评分（0-100）：

- `infected=false`：25 分
- `activeThreats=0`：20 分
- `firewallEnabled=true`：15 分
- `isActive=true`：10 分
- `isUpToDate=true`：10 分
- `encryptedApplications=true`：10 分
- `networkStatus=connected`：10 分

判定规则：

- `score >= threshold`：通过
- `score < threshold`：失败，封禁对应 NetBird 用户（`is_blocked=true`）

## 5. 快速开始

在仓库根目录执行：

```bash
export NETBIRD_URL="https://netbird.example.com"
export NETBIRD_TOKEN="nbp_xxxxxxxxx"
export S1_API_URL="https://usea1-partners.sentinelone.net"
export S1_API_TOKEN="xxxxxxxxx"
```

### 5.1 配置官方 EDR 集成

```bash
python3 deploy/sentinelone_netbird_integration.py configure \
  --netbird-url "$NETBIRD_URL" \
  --netbird-token "$NETBIRD_TOKEN" \
  --s1-api-url "$S1_API_URL" \
  --s1-api-token "$S1_API_TOKEN" \
  --group-id <netbird_group_id> \
  --last-synced-interval 24 \
  --require-firewall-enabled \
  --require-is-active
```

### 5.2 仅审计（不封禁）

```bash
python3 deploy/sentinelone_netbird_integration.py audit \
  --netbird-url "$NETBIRD_URL" \
  --netbird-token "$NETBIRD_TOKEN" \
  --s1-api-url "$S1_API_URL" \
  --s1-api-token "$S1_API_TOKEN" \
  --report-json /tmp/s1_netbird_audit.json
```

### 5.3 强制执行（低于 90 分封禁）

先 dry-run：

```bash
python3 deploy/sentinelone_netbird_integration.py enforce \
  --netbird-url "$NETBIRD_URL" \
  --netbird-token "$NETBIRD_TOKEN" \
  --s1-api-url "$S1_API_URL" \
  --s1-api-token "$S1_API_TOKEN" \
  --score-threshold 90 \
  --dry-run \
  --report-json /tmp/s1_enforce_dryrun.json
```

确认后正式执行：

```bash
python3 deploy/sentinelone_netbird_integration.py enforce \
  --netbird-url "$NETBIRD_URL" \
  --netbird-token "$NETBIRD_TOKEN" \
  --s1-api-url "$S1_API_URL" \
  --s1-api-token "$S1_API_TOKEN" \
  --score-threshold 90 \
  --auto-unblock \
  --report-json /tmp/s1_enforce_result.json
```

## 6. 常用参数

- 通用：
  - `--timeout`：HTTP 超时秒数
  - `--max-active-threats`：允许的最大活跃威胁数
  - `--allow-infected`：允许 infected（默认不允许）
  - `--require-firewall-enabled`
  - `--require-is-active`
  - `--require-up-to-date`
  - `--network-status connected|disconnected|quarantined`
  - `--operational-state <value>`
- `enforce` 专用：
  - `--score-threshold`：默认 90
  - `--dry-run`：仅输出，不落库变更
  - `--auto-unblock`：分数恢复后自动解封

## 7. 定时任务示例（cron）

每 15 分钟执行一次，低于阈值自动封禁：

```cron
*/15 * * * * cd /path/to/netbird && /usr/bin/python3 deploy/sentinelone_netbird_integration.py enforce \
  --netbird-url "$NETBIRD_URL" \
  --netbird-token "$NETBIRD_TOKEN" \
  --s1-api-url "$S1_API_URL" \
  --s1-api-token "$S1_API_TOKEN" \
  --score-threshold 90 \
  --auto-unblock \
  --report-json /var/log/s1_enforce_result.json >> /var/log/s1_enforce.log 2>&1
```

## 8. 常见问题

- `404 /api/integrations/edr/sentinelone`
  - 说明当前 NetBird 部署未开放该路由；请使用 `audit` 或 `enforce` 模式。
- `401/403`
  - 检查 `NETBIRD_TOKEN` 是否有效、是否管理员权限；检查 `S1_API_TOKEN` 是否可访问 agents API。
- 匹配不到 NetBird 机器
  - 目前使用主机名匹配（去域名前缀后比较），请确保 SentinelOne 与 NetBird 主机名一致。

## 9. 安全建议

- Token 不要写入代码仓库，统一使用环境变量或 Secret 管理系统。
- 建议先 `--dry-run` 再正式封禁。
- 生产环境建议开启审计日志，保留 `--report-json` 输出用于追溯。
