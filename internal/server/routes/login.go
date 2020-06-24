package routes

import (
	"fmt"
	"net/http"

	"github.com/go-macaron/csrf"
	"github.com/pkg/errors"
	"gopkg.in/macaron.v1"

	"github.com/stregouet/hydra-ldap/internal/config"
	"github.com/stregouet/hydra-ldap/internal/hydra"
	"github.com/stregouet/hydra-ldap/internal/ldap"
)

func LoginGet(cfg *config.Config) func(ctx *macaron.Context, x csrf.CSRF) {
	return func(ctx *macaron.Context, x csrf.CSRF) {
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
	}
}

func LoginPost(cfg *config.Config) func(ctx *macaron.Context, x csrf.CSRF, ldapcfg *ldap.Config) {
	return func(ctx *macaron.Context, x csrf.CSRF, ldapcfg *ldap.Config) {
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
	}
}
