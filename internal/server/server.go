package server

import (
	"fmt"
	"net/http"
	"os"

	"github.com/go-macaron/csrf"
	"github.com/go-macaron/session"
	"github.com/pkg/errors"
	"gopkg.in/macaron.v1"

	"github.com/stregouet/hydra-ldap/internal/config"
	"github.com/stregouet/hydra-ldap/internal/hydra"
	"github.com/stregouet/hydra-ldap/internal/ldap"
	"github.com/stregouet/hydra-ldap/internal/logging"
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
	m.Map(&cfg.Ldap)
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
	m.Combo("/auth/login").Get(func(ctx *macaron.Context, x csrf.CSRF) {
		l := fromReq(ctx)
		challenge := ctx.Query("login_challenge")
		if challenge == "" {
			l.Info().Msg("missing login challenge")
			ctx.Error(http.StatusBadRequest, "missing login challenge")
			return
		}
		resp, err := hydra.GetLoginRequest(ctx.Req.Context(), &cfg.Hydra, challenge)
		switch errors.Cause(err) {
		case nil:
			break
		case hydra.ErrChallengeNotFound:
			l.Error().Err(err).Str("challenge", challenge).Msg("Unknown login challenge in the OAuth2 provider ")
			ctx.Error(http.StatusBadRequest, "unknown login challenge")
			return
		case hydra.ErrChallengeExpired:
			l.Info().Err(err).Str("challenge", challenge).Msg("Login challenge has been used already in the OAuth2 provider")
			ctx.Error(http.StatusBadRequest, "Login challenge has been used already")
			return
		default:
			l.Error().Err(err).Str("challenge", challenge).Msg("Failed to initiate an OAuth2 login request")
			ctx.Error(http.StatusInternalServerError, "internal server error")
			return
		}

		if resp.Skip {
			redirectURL, err := hydra.AcceptLoginRequest(ctx.Req.Context(), &cfg.Hydra, false, resp.Subject, challenge)
			if err != nil {
				l.Error().Str("challenge", challenge).Err(err).Msg("error making accept login request against hydra ")
				ctx.Error(http.StatusInternalServerError, "internal server error")
				return
			} else {
				l.Info().Str("challenge", challenge).Msg("login UI was skipped")
				ctx.Redirect(redirectURL, http.StatusFound)
				return
			}
		}

		ctx.Data["Title"] = "login-sso"
		ctx.Data["csrf_token"] = x.GetToken()
		ctx.Data["challenge"] = challenge
		ctx.Data["login_url"] = ctx.URLFor("login_form")
		ctx.Data["client_id"] = resp.Client.Id
		ctx.Data["client_name"] = resp.Client.Name
		ctx.HTML(200, "login")
	}).Post(csrf.Validate, func(ctx *macaron.Context, x csrf.CSRF, ldapcfg *ldap.Config) {
		l := fromReq(ctx)
		challenge := ctx.Query("challenge")
		username := ctx.Query("username")
		password := ctx.Query("password")
		clientId := ctx.Query("client_id")
		clientName := ctx.Query("client_name")

		if challenge == "" {
			l.Info().Msg("missing login challenge")
			ctx.Error(http.StatusBadRequest, "missing login challenge")
			return
		}

		ctx.Data["Title"] = "login-sso"
		ctx.Data["csrf_token"] = x.GetToken()
		ctx.Data["challenge"] = challenge
		ctx.Data["login_url"] = ctx.URLFor("login_form")
		ctx.Data["client_id"] = clientId
		ctx.Data["client_name"] = clientName

		err := ldapcfg.NewClientWithContext(ctx.Req.Context()).
			WithAppId(clientId).
			IsAuthorized(username, password)
		switch err {
		case nil:
			remember := ctx.Query("rememberme") != ""
			// XXX `subject` parameter could be either email or uid is this a problem?
			redirectURL, err := hydra.AcceptLoginRequest(
				ctx.Req.Context(),
				&cfg.Hydra,
				remember,
				username,
				challenge,
			)
			if err != nil {
				l.Error().Str("challenge", challenge).Err(err).Msg("error making accept login request against hydra ")
				ctx.Data["error"] = true
				ctx.Data["msg"] = err.Error()
				ctx.HTML(http.StatusInternalServerError, "login")
			} else {
				ctx.Redirect(redirectURL, http.StatusFound)
			}
		case ldap.ErrUnauthorize:
			l.Debug().Str("challenge", challenge).Msg("unable to authorize")
			ctx.Data["error"] = true
			ctx.Data["msg"] = fmt.Sprintf("user `%s` is not authorized to access this app", username)
			ctx.HTML(http.StatusUnauthorized, "login")
		case ldap.ErrUserNotFound, ldap.ErrInvalidCredentials:
			l.Debug().Str("challenge", challenge).Msg("unable to authentificate")
			ctx.Data["error"] = true
			ctx.Data["msg"] = "bad username or password"
			ctx.HTML(http.StatusUnauthorized, "login")
		default:
			l.Error().Str("challenge", challenge).Err(err).Msg("error trying to authentificate")
			ctx.Data["error"] = true
			ctx.Data["msg"] = err.Error()
			ctx.HTML(http.StatusInternalServerError, "login")
		}
	}).Name("login_form")

	m.Combo("/auth/consent").Get(func(ctx *macaron.Context, ldapcfg *ldap.Config) {
		l := fromReq(ctx)
		challenge := ctx.Query("consent_challenge")
		if challenge == "" {
			l.Info().Msg("missing consent challenge")
			ctx.Error(http.StatusBadRequest, "missing consent challenge")
			return
		}

		resp, err := hydra.GetConsentRequest(ctx.Req.Context(), &cfg.Hydra, challenge)
		switch errors.Cause(err) {
		case nil:
			break
		case hydra.ErrChallengeNotFound:
			l.Error().Err(err).Str("challenge", challenge).
				Msg("Unknown consent challenge in the OAuth2 provider ")
			ctx.Error(http.StatusBadRequest, "unknown login challenge")
			return
		case hydra.ErrChallengeExpired:
			l.Info().Err(err).Str("challenge", challenge).
				Msg("Consent challenge has been used already in the OAuth2 provider")
			ctx.Error(http.StatusBadRequest, "Login challenge has been used already")
			return
		default:
			l.Error().Err(err).Str("challenge", challenge).
				Msg("Failed to initiate an OAuth2 consent request")
			ctx.Error(http.StatusInternalServerError, "internal server error")
			return
		}
		ctx.Data["Title"] = "login-sso"
		ctx.Data["client_name"] = resp.Client.Name

		claims, err := ldapcfg.NewClientWithContext(ctx.Req.Context()).
			WithAppId(resp.Client.Id).
			FindOIDCClaims(resp.Subject)
		switch errors.Cause(err) {
		case nil:
			break
		case ldap.ErrUnauthorize:
			l.Debug().Str("challenge", challenge).Msg("unable to authorize during consent flow")
			ctx.Data["error"] = true
			ctx.Data["msg"] = fmt.Sprintf("user `%s` is not authorized to access this app", resp.Subject)
			ctx.HTML(http.StatusUnauthorized, "message")
			return
		default:
			l.Error().Err(err).Str("challenge", challenge).
				Msg("error fetching claim from ldap")
			ctx.Error(http.StatusInternalServerError, "internal server error")
			return
		}
		claims = hydra.FilterClaims(&cfg.Hydra, claims, resp.RequestedScopes)
		redirectURL, err := hydra.AcceptConsentRequest(
			ctx.Req.Context(),
			&cfg.Hydra,
			challenge,
			!resp.Skip,
			resp.RequestedScopes,
			claims,
		)
		if err != nil {
			l.Error().Str("challenge", challenge).Err(err).Msg("error making accept consent request against hydra ")
			ctx.Error(http.StatusInternalServerError, "internal server error")
		}
		ctx.Redirect(redirectURL, http.StatusFound)
	}).Name("consent_form")

}
