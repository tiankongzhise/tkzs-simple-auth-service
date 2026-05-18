# tkzs-simple-auth-service

自制轻量级统一鉴权、限流与服务治理平台，使用 Go 开发，面向接入 APISIX 的中小型服务集群。

## 当前状态

项目按《自制授权限流开发文档.md》和《鉴权限流产品文档.md》逐项开发。当前优先级：

1. 搭建 Go 工程、配置与运行环境。
2. 实现所有 Redis Key 的 `serviceCode` 前缀隔离。
3. 实现基础 HTTP 服务、健康检查、统一响应。
4. 逐步补齐登录鉴权、JWT 自动续签、M2M、OIDC、限流、RBAC、服务治理和 UI。

## 环境要求

- Go 1.20+
- PostgreSQL 12+
- Redis 6.0+
- Windows Server 2016+、CentOS 7+ 或兼容系统

本机验证环境：

```powershell
go version
```

## 快速开始

复制示例配置：

```powershell
Copy-Item config.example.yaml config.yaml
Copy-Item .env.example .env
```

按本地 PostgreSQL、Redis、JWT 证书路径修改 `config.yaml`。私钥、公钥、`.env` 和本地配置文件不会进入仓库。

下载依赖：

```powershell
go mod download
```

运行测试：

```powershell
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

默认读取 `./config.yaml`，也可以通过环境变量指定：

```powershell
$env:AUTH_LIMIT_CONFIG="./config.yaml"
go run ./cmd/server
```

## Redis Key 规范

所有 Redis Key 必须通过统一工具生成，并满足：

```text
{serviceCode}:{module}:{submodule}:{identifier}
```

示例：

```text
authlimit:jwt:access:{jti}
authlimit:limit:bucket:{serviceId}:{dimension}:{value}
```

业务代码禁止直接访问无 `serviceCode` 前缀的 Key。

## 开发提交约定

开发按功能拆分提交，不在全部功能完成后一次性提交。每个提交应包含：

- 本次实现的功能点。
- 相关测试或验证方式。
- 与开发文档条目的对应关系。
