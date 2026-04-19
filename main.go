package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/czertainly/signer-poc/internal/tsacrypto"
	"github.com/czertainly/signer-poc/internal/tsp"
)

func main() {
	chain, err := tsacrypto.Generate()
	if err != nil {
		log.Fatal(err)
	}

	app := tsp.NewApp(chain, tsp.DefaultConfig())

	port := envOrDefault("PORT", "8080")
	log.Printf("signer-poc listening on :%s", port)

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	listenErr := make(chan error, 1)
	go func() { listenErr <- app.Listen(":" + port) }()
	select {
	case err := <-listenErr:
		log.Fatal(err)
	case <-quit:
	}
	if err := app.ShutdownWithTimeout(5 * time.Second); err != nil {
		log.Printf("shutdown error: %v", err)
	}
}

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
