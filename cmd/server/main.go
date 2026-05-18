package main

import (
	"fmt"
	"log"

	"github.com/hbc-thinkbook/tkzs-simple-auth-service/config"
	"github.com/hbc-thinkbook/tkzs-simple-auth-service/internal/bootstrap"
	"github.com/hbc-thinkbook/tkzs-simple-auth-service/internal/database"
	"github.com/hbc-thinkbook/tkzs-simple-auth-service/internal/server"
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

	router := server.NewRouter(cfg)
	addr := fmt.Sprintf(":%d", cfg.Server.Port)
	if err := router.Run(addr); err != nil {
		log.Fatalf("run server: %v", err)
	}
}
