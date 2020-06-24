package server

import (
	"time"

	"github.com/rs/zerolog"
	"gopkg.in/macaron.v1"

	"github.com/stregouet/hydra-ldap/internal/logging"
)

func zerologMiddleware(ctx *macaron.Context) {
	// Create a copy of the logger (including internal context slice)
	// to prevent data race when using UpdateContext.
	l := logging.Logger.With().Logger()
	ctx.Req = macaron.Request{ctx.Req.WithContext(l.WithContext(ctx.Req.Context()))}

	start := time.Now()

	logging.Info().Str("uri", ctx.Req.RequestURI).Str("verb", ctx.Req.Method).Msg("request started")

	rw := ctx.Resp.(macaron.ResponseWriter)
	ctx.Next()

	var evt *zerolog.Event
	if rw.Status() >= 500 {
		evt = logging.Error()
	} else {
		evt = logging.Info()
	}
	evt.Str("uri", ctx.Req.RequestURI).Str("verb", ctx.Req.Method).Int("status", rw.Status()).Dur("duration", time.Since(start)).Msg("request ended")
}
