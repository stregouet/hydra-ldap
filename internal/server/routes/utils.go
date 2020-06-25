package routes

import (
	"github.com/go-macaron/csrf"
	"gopkg.in/macaron.v1"
)

type CSRFHandler func(ctx *macaron.Context, x csrf.CSRF)
