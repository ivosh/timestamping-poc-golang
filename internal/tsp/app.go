package tsp

import (
	"github.com/examle.com/timestamping-poc-golang/internal/tsacrypto"
	"github.com/gofiber/fiber/v2"
)

func NewApp(chain *tsacrypto.TSAChain, cfg Config) *fiber.App {
	svc := NewService(chain, cfg)
	app := fiber.New(fiber.Config{DisableStartupMessage: true})
	app.Post("/api/v1/protocols/tsp/:profileName/sign", NewHandler(svc))
	return app
}
