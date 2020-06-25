package routes

import (
	"github.com/go-macaron/csrf"
	"github.com/rs/zerolog"
	"gopkg.in/macaron.v1"
)

type CSRFHandler func(ctx *macaron.Context, x csrf.CSRF)

func fromReq(ctx *macaron.Context) *zerolog.Logger {
	return zerolog.Ctx(ctx.Req.Context())
}
