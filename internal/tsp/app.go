package tsp

import (
	"github.com/czertainly/signer-poc/internal/tsacrypto"
	"github.com/gofiber/fiber/v2"
)

func NewApp(id *tsacrypto.TSAIdentity) *fiber.App {
	svc := NewService(id)
	app := fiber.New(fiber.Config{DisableStartupMessage: true})
	app.Post("/api/v1/protocols/tsp/:profileName/sign", NewHandler(svc))
	return app
}
