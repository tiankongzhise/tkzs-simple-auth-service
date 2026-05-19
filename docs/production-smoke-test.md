# 生产冒烟测试说明

本文档用于记录并复用鉴权限流服务生产环境的冒烟测试流程。生产地址：
`https://auth-limit.baichengedu.com`。

## 验证目标

- 确认生产服务可通过公网 HTTPS 正常访问。
- 确认 OIDC、JWKS、Prometheus 指标、管理后台静态资源、登录鉴权、管理接口、M2M 签名校验、服务治理、限流和统计链路均已接通。
- 所有会写入生产环境的测试数据都使用统一前缀，便于识别和清理。

## 影响范围

完整冒烟会创建临时生产数据，并产生系统自然运行记录。仅在允许这些影响时执行。

会创建并清理的临时业务资源：

- 测试用户。
- 测试角色。
- 测试 APP 及一次性 APP Secret。
- 测试服务。

会保留的系统记录或缓存：

- 登录 Token 和 `last_login` 变化。
- 操作日志、鉴权日志等审计记录。
- Redis M2M nonce key。
- Redis 限流桶 key。
- 限流日志和限流统计记录。

## 命名规则

所有临时业务资源统一使用时间戳前缀：

```text
smoke_<yyyyMMddHHmmss>
```

示例：

```text
smoke_20260519153000
smoke_20260519153000_role
smoke_20260519153000_app
smoke_20260519153000_service
```

## 公开端点检查

以下端点应返回 HTTP 200：

```bash
curl -i https://auth-limit.baichengedu.com/health
curl -i https://auth-limit.baichengedu.com/.well-known/openid-configuration
curl -i https://auth-limit.baichengedu.com/oauth2/jwks
curl -i https://auth-limit.baichengedu.com/metrics
curl -i https://auth-limit.baichengedu.com/ui/
curl -i https://auth-limit.baichengedu.com/ui/styles.css
curl -i https://auth-limit.baichengedu.com/ui/app.js
```

关键预期：

- `/health` 返回 `code: 0`、`status: ok`，服务标识为 `authlimit`。
- OIDC discovery 的 issuer 为 `https://auth-limit.baichengedu.com`。
- JWKS 至少返回一个 `alg: RS256` 的 RSA 公钥。
- `/ui/`、`/ui/styles.css`、`/ui/app.js` 均可正常加载。

## 预期错误检查

以下检查不创建数据，用于确认路由和保护逻辑正常：

```bash
curl -i https://auth-limit.baichengedu.com/api/users
curl -i -X POST https://auth-limit.baichengedu.com/oauth2/token
curl -i -X POST https://auth-limit.baichengedu.com/oidc/limit/verify
```

关键预期：

- 未带 `Authorization` 访问 `/api/users` 返回 401。
- 未带 grant 访问 `/oauth2/token` 返回 OAuth 错误。
- 未带必需 JSON 访问 `/oidc/limit/verify` 返回 400。

## 完整冒烟流程

1. 登录 admin。若生产环境已修改种子密码，使用当前有效的生产管理员账号。
2. 调用 `POST /api/users/register` 注册临时测试用户。
3. 调用 `POST /api/auth/login` 登录临时测试用户。
4. 调用 `GET /api/auth/verify` 验证临时测试用户 Access Token。
5. 使用临时测试用户 Token 调用 `GET /api/users`，确认普通用户可读取自己的用户记录。
6. 使用 admin Token 创建临时角色，授予 `app:manage`、`service:manage`、`statistics:read` 权限，并把该角色分配给临时测试用户。随后重新登录临时测试用户，让新 Token 携带这些权限。
7. 使用临时测试用户 Token 调用 `POST /api/apps` 创建临时 APP，保存返回的 `appId` 和一次性 `appSecret`。
8. 使用临时测试用户 Token 调用 `POST /api/services` 创建临时服务：

   ```json
   {
     "name": "smoke_<timestamp> service",
     "code": "smoke_<timestamp>",
     "baseUrl": "https://auth-limit.baichengedu.com",
     "healthPath": "/health",
     "healthCheckInterval": 30
   }
   ```

9. 使用 admin Token 调用 `POST /api/services/{id}/approve` 审批临时服务。
10. 调用 `GET /api/services/discover` 验证服务发现行为。服务发现只返回 `approved=true`、`status=approved` 且 `healthStatus=healthy` 的服务，因此刚审批的临时服务在健康检查尚未标记为 `healthy` 前可能不会出现在发现列表中。
11. 按项目 M2M 算法生成签名：

   ```text
   canonical = appSecret + "&" + timestamp + "&" + sorted(key=value params)
   sign = hex(HMAC-SHA256(key=appSecret, message=canonical))
   ```

12. 调用 `POST /api/auth/m2m`，请求头带 `appId`、`timestamp`、`sign`，请求体使用小型 JSON：

    ```json
    {
      "scenario": "production-smoke",
      "nonce": "smoke_<timestamp>"
    }
    ```

13. 使用完全相同的 M2M 请求重复调用一次，第二次应因重放保护被拒绝。
14. 对临时服务调用 `POST /oidc/limit/verify`：

    ```json
    {
      "serviceId": "<temporary service id>",
      "path": "/smoke",
      "method": "GET",
      "ip": "127.0.0.1",
      "userId": "<temporary user id>",
      "appId": "<temporary app id>"
    }
    ```

15. 确认限流响应 `allowed: true`，并包含 `X-RateLimit-Remaining` 和 `X-RateLimit-Reset` 响应头。
16. 使用授权 Token 调用 `GET /api/limit-statistics?serviceId=<temporary service id>`，确认产生限流统计。

## 清理步骤

按依赖关系反向删除临时资源：

1. 使用 `DELETE /api/services/{id}` 删除临时服务。
2. 使用 `DELETE /api/apps/{id}` 删除临时 APP。
3. 使用 admin Token 调用 `DELETE /api/users/{id}` 删除临时用户。
4. 使用 `DELETE /api/roles/{id}` 删除临时角色。

清理后，常规业务列表中不应再出现活跃的 `smoke_<timestamp>` 资源。审计、Token、M2M nonce、限流桶和限流统计记录按设计保留。

## 2026-05-19 生产冒烟记录

执行前缀：`smoke_20260519144320`。

通过项：

- `/health` 返回 `service=authlimit`、`version=v0.1.0`。
- OIDC discovery 返回 issuer `https://auth-limit.baichengedu.com`。
- JWKS 返回 1 个 `RS256` key。
- `/metrics` 正常返回 Prometheus 指标。
- `/ui/`、`/ui/styles.css`、`/ui/app.js` 均返回 200。
- 未登录访问 `/api/users` 返回 401。
- 缺参访问 `/oidc/limit/verify` 返回 400。
- admin 登录成功。
- 成功查到 `app:manage`、`service:manage`、`statistics:read` 权限。
- 成功注册临时用户并完成登录、Token verify、自身用户列表查询。
- 成功创建临时角色并分配给临时用户，重新登录后 Token 携带预期权限。
- 成功创建临时 APP 和临时服务，临时服务初始状态为 `pending`。
- admin 成功审批临时服务，审批后状态为 `approved`。
- M2M 有效签名验证成功。
- 完全相同的 M2M 请求第二次调用被拒绝，重放保护生效。
- 限流校验返回 `allowed: true`，并返回 `X-RateLimit-Remaining=99`、`X-RateLimit-Reset=1779173008`。
- 限流统计查询返回 3 条统计记录。
- 临时服务、临时 APP、临时用户、临时角色均已清理成功。

复核说明：

- 首次脚本中 `/ui/` 被标记为失败，是 PowerShell 中文内容匹配的编码误判；只读复核确认 `/ui/` 返回 200 且页面内容正常。
- 首次脚本中 `/oauth2/token` 缺参检查被标记为失败，是错误响应体读取断言过窄；只读复核确认该端点缺参返回 HTTP 400。
- `GET /api/services/discover?name=smoke_20260519144320` 返回 0 条，是因为服务发现要求服务健康状态为 `healthy`。本次临时服务刚审批完成时仍为 `unknown`，符合当前实现。

## 排查建议

- 本地沙箱网络访问失败不能证明生产环境不可用，应在具备公网 HTTPS 访问权限的环境重试。
- admin 登录失败通常表示生产环境已修改种子密码，应改用当前有效的管理员账号。
- M2M 第一次成功、第二次相同请求失败，表示重放保护正常。
- 新审批服务未出现在服务发现列表时，先检查 `healthStatus` 是否仍为 `unknown`；服务发现只返回已审批且健康的服务。
- 限流成功但统计暂未出现时，可等待短时间后重试统计查询。
- 清理时出现 403，使用 admin Token 重试。
