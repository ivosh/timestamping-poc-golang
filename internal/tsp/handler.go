package tsp

import (
	"encoding/asn1"
	"errors"
	"mime"

	"github.com/digitorus/timestamp"
	"github.com/gofiber/fiber/v2"
)

const (
	failBadDataFormat   = 5
	failBadRequest      = 2
	failUnacceptedPolicy = 15
	failTimeNotAvailable = 14
	failSystemFailure   = 25
)

type pkiStatusInfo struct {
	Status   int
	FailInfo asn1.BitString `asn1:"optional"`
}

type timeStampRespStatus struct {
	Status pkiStatusInfo
}

func buildRejection(failBit int) ([]byte, error) {
	failureInfo := asn1.BitString{
		Bytes:     []byte{0, 0, 0, 0},
		BitLength: 32,
	}
	failureInfo.Bytes[failBit/8] |= 1 << (7 - uint(failBit)%8)
	return asn1.Marshal(timeStampRespStatus{
		Status: pkiStatusInfo{Status: 2, FailInfo: failureInfo},
	})
}

func NewHandler(svc *Service) fiber.Handler {
	return func(c *fiber.Ctx) error {
		mt, _, _ := mime.ParseMediaType(c.Get("Content-Type"))
		if mt != "application/timestamp-query" {
			return c.Status(400).SendString("expected application/timestamp-query")
		}

		c.Set("Content-Type", "application/timestamp-reply")

		body := make([]byte, len(c.Body()))
		copy(body, c.Body())

		req, err := timestamp.ParseRequest(body)
		if err != nil {
			resp, _ := buildRejection(failBadDataFormat)
			return c.Status(200).Send(resp)
		}

		resp, err := svc.Sign(req)
		if err != nil {
			bit := failSystemFailure
			switch {
			case errors.Is(err, ErrDuplicateNonce):
				bit = failBadRequest
			case errors.Is(err, ErrUnacceptedPolicy):
				bit = failUnacceptedPolicy
			case errors.Is(err, ErrTimeNotAvailable):
				bit = failTimeNotAvailable
			}
			rej, _ := buildRejection(bit)
			return c.Status(200).Send(rej)
		}

		return c.Status(200).Send(resp)
	}
}
