# tkzs-simple-auth-service

自制轻量级统一鉴权、限流与服务治理后端服务，使用 Go 开发，面向接入 APISIX 的中小型服务集群。

## 当前状态

项目当前已经具备可部署的后端核心能力，已在 `https://auth-limit.baichengedu.com` 完成健康检查、鉴权、M2M、限流、黑白名单、服务管理和 OIDC 基础端点验证。

已实现：

- PostgreSQL 自动迁移，启动时初始化系统权限、管理员角色和默认 admin 用户。
- Web 登录、Access Token、Refresh Token、刷新轮换、登出吊销、Token 校验。
- Access Token 临近过期自动续签，续签 Token 通过响应头返回。
- M2M APP 创建、Secret 重置、HMAC-SHA256 签名校验、时间戳校验和重放拒绝。
- OIDC/OAuth2 基础端点：discovery、authorize、token、jwks、userinfo。
- APP 管理、服务注册/审核/发现、黑名单、白名单管理接口。
- `/ui/` 内嵌轻量管理后台，登录后可查看用户、APP、角色、OIDC Client、服务、日志、统计和健康检测数据。
- 用户注册、用户管理、角色权限管理、OIDC Client 管理接口。
- 日志查询、健康检测日志查询、限流统计查询和 Prometheus `/metrics` 指标。
- 服务周期性健康检测任务，状态变化后同步服务发现列表。
- Redis 分布式令牌桶限流，Redis 异常时本地令牌桶降级。
- 动态限流规则 CRUD，服务级启用规则运行时生效，未配置时继承全局默认令牌桶配置。
- Redis Key 统一 `serviceCode` 前缀隔离，SafeRedisClient 会拦截跨前缀访问。
- RBAC 中间件和权限点初始化，管理接口按权限保护。
- Linux amd64 宝塔部署包构建，单个静态 Go 二进制运行。

当前限制：

- `/ui/` 是轻量单页后台，聚焦核心数据查看和入口操作，不是完整前端框架。
- 操作日志、鉴权日志表已可查询，业务侧精细审计埋点可继续按事件类型补充。

## 用户文档

- [API 使用说明](docs/api-usage-guide.md)：面向开发者、网关接入方和自动化脚本，覆盖鉴权、限流、服务注册/发现、OIDC、M2M 和 APISIX 对接。
- [界面操作说明](docs/ui-usage-guide.md)：面向管理员、运营和服务负责人，按管理后台菜单说明用户、APP、角色、OIDC Client、服务、限流、黑白名单、日志和统计操作。

## 环境要求

- Go 1.25+，本机验证使用 Go 1.26.2。
- PostgreSQL 12+。
- Redis 6.0+。
- 部署目标建议 Linux amd64；当前已验证宝塔面板反向代理部署。

运行时仍依赖 PostgreSQL 和 Redis。“无外部依赖部署包”指 Go 服务二进制无需服务器安装 Go 或动态库。

## 快速开始

复制示例配置：

```powershell
Copy-Item config.example.yaml config.yaml
Copy-Item .env.example .env
```

按本地 PostgreSQL、Redis、JWT 证书路径修改 `.env`。`config.yaml` 默认通过环境变量占位符读取 `.env` 中的实际值。

下载依赖：

```powershell
go mod download
```

运行测试：

```powershell
$env:GOCACHE="$PWD\.gocache"
go test ./...
```

启动服务：

```powershell
go run ./cmd/server
```

默认健康检查：

```text
GET http://127.0.0.1:8080/health
```

## 配置入口

默认读取当前运行目录下的 `./config.yaml`，并自动加载同目录 `.env`。

也可以通过环境变量指定配置文件：

```powershell
$env:AUTH_LIMIT_CONFIG="./config.yaml"
go run ./cmd/server
```

生产环境关键配置示例：

```text
AUTH_LIMIT_SERVER_HOST=https://auth-limit.baichengedu.com
AUTH_LIMIT_SERVER_PORT=9312
AUTH_LIMIT_RUN_MODE=prod
AUTH_LIMIT_OIDC_ISSUER=https://auth-limit.baichengedu.com
AUTH_LIMIT_JWT_PRIVATE_KEY_PATH=./certs/jwt_private.pem
AUTH_LIMIT_JWT_PUBLIC_KEY_PATH=./certs/jwt_public.pem
```

`run_mode=prod` 时，`server.host` 和 `oidc.issuer` 必须使用 HTTPS。

## API 概览

基础接口：

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/health` | 健康检查 |
| GET | `/metrics` | Prometheus 指标 |
| GET | `/ui/` | 内嵌轻量管理后台 |

鉴权接口：

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/api/auth/login` | 用户登录 |
| POST | `/api/auth/refresh` | Refresh Token 续签 |
| GET | `/api/auth/verify` | Access Token 校验 |
| POST | `/api/auth/logout` | 登出并吊销 Token |
| POST | `/api/auth/m2m` | M2M 签名鉴权 |

OIDC/OAuth2 接口：

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/.well-known/openid-configuration` | OIDC discovery |
| GET | `/oauth2/authorize` | Authorization Code 授权端点 |
| POST | `/oauth2/token` | authorization_code / refresh_token 换取 Token |
| GET | `/oauth2/jwks` | JWKS 公钥 |
| GET | `/oauth2/userinfo` | 用户信息 |

管理与治理接口需要 `Authorization: Bearer {accessToken}`：

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/api/users/register` | 用户注册 |
| GET | `/api/users` | 用户列表 |
| GET/PUT/DELETE | `/api/users/:id` | 用户详情、资料更新、删除 |
| PUT | `/api/users/:id/status` | 启用或禁用用户 |
| PUT | `/api/users/:id/password` | 修改用户密码 |
| PUT | `/api/users/:id/roles` | 分配用户角色 |
| GET | `/api/permissions` | 权限列表 |
| GET/POST | `/api/roles` | 角色列表、创建 |
| GET/PUT/DELETE | `/api/roles/:id` | 角色详情、更新、删除 |
| GET/POST | `/api/apps` | APP 列表、创建 |
| GET/PUT/DELETE | `/api/apps/:id` | APP 详情、更新、删除 |
| POST | `/api/apps/:id/reset-secret` | 重置 APP Secret |
| PUT | `/api/apps/:id/roles` | 分配 APP 角色 |
| GET/POST | `/api/oidc-clients` | OIDC Client 列表、创建 |
| GET/PUT/DELETE | `/api/oidc-clients/:id` | OIDC Client 详情、更新、删除 |
| POST | `/api/oidc-clients/:id/reset-secret` | 重置 OIDC Client Secret |
| GET/POST | `/api/services` | 服务列表、注册 |
| GET | `/api/services/discover` | 服务发现 |
| GET/PUT/DELETE | `/api/services/:id` | 服务详情、更新、删除 |
| POST | `/api/services/:id/approve` | 服务审核 |
| GET/POST | `/api/limit-rules` | 限流规则列表、创建 |
| GET/PUT/DELETE | `/api/limit-rules/:id` | 限流规则详情、更新、删除 |
| GET/POST | `/api/blacklists` | 黑名单列表、创建 |
| DELETE | `/api/blacklists/:id` | 删除黑名单 |
| GET/POST | `/api/whitelists` | 白名单列表、创建 |
| DELETE | `/api/whitelists/:id` | 删除白名单 |
| GET | `/api/logs` | 日志查询 |
| GET | `/api/health-checks` | 健康检测日志查询 |
| GET | `/api/limit-statistics` | 限流统计查询 |

限流校验接口：

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/oidc/limit/verify` | APISIX 或业务网关调用的限流校验 |

## 宝塔部署包

Linux amd64 静态编译：

```powershell
$env:GOOS="linux"
$env:GOARCH="amd64"
$env:GOAMD64="v1"
$env:CGO_ENABLED="0"
$env:GOCACHE="./.gocache"
go build -tags=nomsgpack -p=1 -trimpath -buildvcs=false -ldflags="-s -w -buildid=" -o dist/authlimit-bt-linux-amd64/authlimit ./cmd/server
```

运行目录需要包含：

```text
authlimit-bt-linux-amd64/
  authlimit
  config.yaml
  .env
  certs/
    jwt_private.pem
    jwt_public.pem
```

宝塔 Go 项目配置：

```text
启动文件：/你的部署目录/authlimit
运行目录：/你的部署目录/
```

## Nginx 反向代理注意事项

OIDC discovery 路径必须反代给 Go 服务，不能被证书验证目录截获。

建议只保留 ACME 验证目录：

```nginx
location ^~ /.well-known/acme-challenge/ {
    root /www/wwwroot/java_node_ssl;
    try_files $uri =404;
}

location = /.well-known/openid-configuration {
    proxy_pass http://127.0.0.1:9312;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
}
```

禁止公网访问证书和密钥：

```nginx
location ^~ /certs/ {
    return 404;
}

location ~* \.(pem|key|crt)$ {
    return 404;
}
```

验证：

```bash
curl https://auth-limit.baichengedu.com/.well-known/openid-configuration
curl https://auth-limit.baichengedu.com/certs/jwt_private.pem
```

预期 discovery 返回 200 JSON，私钥路径返回 404。

## Redis Key 规范

所有 Redis Key 必须通过统一工具生成，并满足：

```text
{serviceCode}:{module}:{submodule}:{identifier}
```

示例：

```text
authlimit:jwt:access:{jti}
authlimit:limit:bucket:{serviceId}:{dimension}:{value}
authlimit:m2m:nonce:{appId}:{timestamp}:{signHash}
```

业务代码禁止直接访问无 `serviceCode` 前缀的 Key。Lua 脚本和批量命令必须校验所有传入 Key。

## 已验证的线上功能

`https://auth-limit.baichengedu.com` 当前已验证：

- `/health` 正常。
- OIDC discovery 返回公网 HTTPS endpoint。
- JWKS 正常返回 RSA 公钥。
- 私钥和公钥路径公网访问返回 404。
- admin 登录、Token 校验、Refresh Token 轮换、登出后 Token 失效。
- APP 创建/删除、M2M 签名校验、M2M 重放拒绝。
- 服务创建/删除、限流校验、黑名单命中、白名单跳过限流。

## 开发提交约定

开发按功能拆分提交，不在全部功能完成后一次性提交。每个提交应包含：

- 本次实现的功能点。
- 相关测试或验证方式。
- 与开发文档条目的对应关系。
