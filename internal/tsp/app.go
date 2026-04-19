package tsp

import (
	"github.com/czertainly/signer-poc/internal/tsacrypto"
	"github.com/gofiber/fiber/v2"
)

func NewApp(chain *tsacrypto.TSAChain, cfg Config) *fiber.App {
	svc := NewService(chain, cfg)
	app := fiber.New(fiber.Config{DisableStartupMessage: true})
	app.Post("/api/v1/protocols/tsp/:profileName/sign", NewHandler(svc))
	return app
}
