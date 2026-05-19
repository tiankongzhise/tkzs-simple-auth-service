package main

import (
	"fmt"
	"log"

	"github.com/hbc-thinkbook/tkzs-simple-auth-service/config"
	"github.com/hbc-thinkbook/tkzs-simple-auth-service/internal/api"
	appsvc "github.com/hbc-thinkbook/tkzs-simple-auth-service/internal/app"
	"github.com/hbc-thinkbook/tkzs-simple-auth-service/internal/auth"
	"github.com/hbc-thinkbook/tkzs-simple-auth-service/internal/bootstrap"
	"github.com/hbc-thinkbook/tkzs-simple-auth-service/internal/database"
	"github.com/hbc-thinkbook/tkzs-simple-auth-service/internal/limiter"
	"github.com/hbc-thinkbook/tkzs-simple-auth-service/internal/listing"
	"github.com/hbc-thinkbook/tkzs-simple-auth-service/internal/m2m"
	"github.com/hbc-thinkbook/tkzs-simple-auth-service/internal/oidc"
	rolesvc "github.com/hbc-thinkbook/tkzs-simple-auth-service/internal/role"
	"github.com/hbc-thinkbook/tkzs-simple-auth-service/internal/server"
	servicesvc "github.com/hbc-thinkbook/tkzs-simple-auth-service/internal/service"
	usersvc "github.com/hbc-thinkbook/tkzs-simple-auth-service/internal/user"
	"github.com/hbc-thinkbook/tkzs-simple-auth-service/pkg/jwtx"
	"github.com/hbc-thinkbook/tkzs-simple-auth-service/pkg/redisx"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	db, err := database.Open(cfg.Postgres)
	if err != nil {
		log.Fatalf("connect postgres: %v", err)
	}
	if err := database.AutoMigrate(db); err != nil {
		log.Fatalf("migrate database: %v", err)
	}
	if err := bootstrap.Initialize(db, cfg); err != nil {
		log.Fatalf("bootstrap system data: %v", err)
	}

	keyBuilder, err := redisx.NewKeyBuilder(cfg.Service.Code)
	if err != nil {
		log.Fatalf("build redis key helper: %v", err)
	}
	redisClient := redisx.NewRedisClient(redisx.RedisClientOptions{
		Addr:         cfg.Redis.Addr,
		Username:     cfg.Redis.Username,
		Password:     cfg.Redis.Password,
		DB:           cfg.Redis.DB,
		DialTimeout:  cfg.Redis.DialTimeout,
		ReadTimeout:  cfg.Redis.ReadTimeout,
		WriteTimeout: cfg.Redis.WriteTimeout,
		PoolSize:     cfg.Redis.PoolSize,
	})
	defer redisClient.Close()
	safeRedis := redisx.NewSafeClient(keyBuilder, redisx.NewRedisExecutor(redisClient))

	jwtManager, err := jwtx.NewManager(cfg.JWT)
	if err != nil {
		log.Fatalf("load jwt keys: %v", err)
	}

	authService := auth.NewService(cfg, auth.NewGormStore(db), safeRedis, jwtManager)
	m2mService := m2m.NewService(cfg, m2m.NewGormStore(db), safeRedis)
	authHandler := api.NewAuthHandler(authService, m2mService)
	oidcService := oidc.NewService(
		cfg,
		jwtManager,
		oidc.NewAuthTokenService(authService),
		oidc.WithStore(oidc.NewGormStore(db)),
		oidc.WithCache(safeRedis),
	)
	oidcHandler := api.NewOIDCHandler(oidcService)
	appService := appsvc.NewService(appsvc.NewGormStore(db))
	appHandler := api.NewAppHandler(appService)
	serviceService := servicesvc.NewService(cfg, servicesvc.NewGormStore(db), safeRedis)
	serviceHandler := api.NewServiceHandler(serviceService)
	listService := listing.NewService(listing.NewGormStore(db), safeRedis)
	listHandler := api.NewListHandler(listService)
	limitService := limiter.NewService(cfg, safeRedis, limiter.WithListChecker(listService))
	limitHandler := api.NewLimitHandler(limitService)
	userService := usersvc.NewService(cfg, usersvc.NewGormStore(db), usersvc.WithCache(safeRedis))
	userPublicHandler := api.NewUserPublicHandler(userService)
	userHandler := api.NewUserHandler(userService)
	roleService := rolesvc.NewService(rolesvc.NewGormStore(db))
	permissionHandler := api.NewPermissionHandler(roleService)
	roleHandler := api.NewRoleHandler(roleService)
	roleAssignmentHandler := api.NewRoleAssignmentHandler(roleService)

	router := server.NewRouter(
		cfg,
		server.WithAuthRoutes(authHandler),
		server.WithOIDCRoutes(oidcHandler),
		server.WithLimitRoutes(limitHandler),
		server.WithAPIRoutes(userPublicHandler),
		server.WithAPIRoutes(userHandler, api.AuthMiddleware(authService)),
		server.WithAPIRoutes(permissionHandler, api.AuthMiddleware(authService)),
		server.WithAPIRoutes(roleHandler, api.AuthMiddleware(authService), api.RequirePermission("role:manage")),
		server.WithAPIRoutes(roleAssignmentHandler, api.AuthMiddleware(authService), api.RequirePermission("role:manage")),
		server.WithAPIRoutes(appHandler, api.AuthMiddleware(authService), api.RequirePermission("app:manage")),
		server.WithAPIRoutes(serviceHandler, api.AuthMiddleware(authService), api.RequirePermission("service:manage")),
		server.WithAPIRoutes(listHandler, api.AuthMiddleware(authService), api.RequirePermission("blacklist:manage")),
	)
	addr := fmt.Sprintf(":%d", cfg.Server.Port)
	if err := router.Run(addr); err != nil {
		log.Fatalf("run server: %v", err)
	}
}
