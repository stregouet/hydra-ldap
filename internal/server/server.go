package server

import (
	"os"

	"github.com/go-macaron/csrf"
	"github.com/go-macaron/session"
	"gopkg.in/macaron.v1"

	"github.com/stregouet/hydra-ldap/internal/config"
	"github.com/stregouet/hydra-ldap/internal/logging"
	"github.com/stregouet/hydra-ldap/internal/server/routes"
)

func Start(cfg *config.Config) {
	macaronEnv := ""
	if !cfg.Dev {
		macaronEnv = "production"
		macaron.Env = macaronEnv
	}
	os.Setenv("MACARON_ENV", macaronEnv)
	m := macaron.NewWithLogger(logging.Logger.With().Str("component", "macaron").Logger())

	setupMiddlewares(m)
	setupRoutes(m, cfg)
	m.Run()
}

func setupMiddlewares(m *macaron.Macaron) {
	m.Use(zerologMiddleware)
	m.Use(macaron.Recovery())
	m.Use(macaron.Static("public"))
	m.Use(macaron.Renderer())
	m.Use(session.Sessioner())
	m.Use(csrf.Csrfer())
}

func setupRoutes(m *macaron.Macaron, cfg *config.Config) {
	m.Combo("/auth/login").
		Get(routes.LoginGet(cfg)).
		Post(csrf.Validate, routes.LoginPost(cfg)).
		Name("login_form")

	m.Combo("/auth/consent").
		Get(routes.ConsentGet(cfg)).
		Post(csrf.Validate, routes.ConsentPost(cfg)).
		Name("consent_form")

	m.Get("/", routes.SelfService(cfg))

	m.Get("/login", routes.SelfServiceLogin(cfg))
	m.Get("/logout", routes.SelfServiceLogout(cfg))
	m.Get("/oidc/callback", routes.SelfServiceOauth(cfg))

	m.Post("/revoke/:clientid", csrf.Validate, routes.SelfServiceRevoke(cfg))
}
