package routes

import (
	"github.com/rs/zerolog"
	"gopkg.in/macaron.v1"
)

func fromReq(ctx *macaron.Context) *zerolog.Logger {
	return zerolog.Ctx(ctx.Req.Context())
}
