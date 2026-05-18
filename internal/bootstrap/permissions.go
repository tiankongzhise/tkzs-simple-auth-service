package bootstrap

import "github.com/hbc-thinkbook/tkzs-simple-auth-service/internal/model"

type PermissionSeed struct {
	Code   string
	Name   string
	Module string
	Action string
}

func SystemPermissions() []PermissionSeed {
	return []PermissionSeed{
		{Code: "user:manage", Name: "用户管理", Module: "user", Action: "manage"},
		{Code: "app:manage", Name: "APP 管理", Module: "app", Action: "manage"},
		{Code: "role:manage", Name: "角色权限管理", Module: "role", Action: "manage"},
		{Code: "service:manage", Name: "服务管理", Module: "service", Action: "manage"},
		{Code: "limit:manage", Name: "限流规则管理", Module: "limit", Action: "manage"},
		{Code: "blacklist:manage", Name: "黑名单管理", Module: "blacklist", Action: "manage"},
		{Code: "log:read", Name: "日志查询", Module: "log", Action: "read"},
		{Code: "health:read", Name: "健康检测查询", Module: "health", Action: "read"},
		{Code: "statistics:read", Name: "限流统计查询", Module: "statistics", Action: "read"},
	}
}

func AdminRole() model.Role {
	return model.Role{
		Code:        model.RoleAdminCode,
		Name:        "超级管理员",
		Description: "系统内置超级管理员角色",
		System:      true,
	}
}
