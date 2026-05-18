package main

import (
	"fmt"
	"log"

	"github.com/hbc-thinkbook/tkzs-simple-auth-service/config"
	"github.com/hbc-thinkbook/tkzs-simple-auth-service/internal/server"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	router := server.NewRouter(cfg)
	addr := fmt.Sprintf(":%d", cfg.Server.Port)
	if err := router.Run(addr); err != nil {
		log.Fatalf("run server: %v", err)
	}
}
