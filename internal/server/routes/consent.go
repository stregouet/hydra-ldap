package routes

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/go-macaron/csrf"
	"github.com/pkg/errors"
	"gopkg.in/macaron.v1"

	"github.com/stregouet/hydra-ldap/internal/config"
	"github.com/stregouet/hydra-ldap/internal/hydra"
	"github.com/stregouet/hydra-ldap/internal/ldap"
	"github.com/stregouet/hydra-ldap/internal/logging"
)

func ConsentGet(cfg *config.Config) CSRFHandler {
	return func(ctx *macaron.Context, x csrf.CSRF) {
		l := logging.FromMacaron(ctx)
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

		clientId := resp.Client.Id
		subject := resp.Subject
		scopes := resp.RequestedScopes
		if resp.Skip {
			redirectURL := accept(ctx, cfg, clientId, subject, challenge, scopes)
			if redirectURL != "" {
				l.Info().Str("challenge", challenge).Msg("consent UI was skipped")
				ctx.Redirect(redirectURL, http.StatusFound)
			}
			return
		}

		ctx.Data["Title"] = "login-sso"
		ctx.Data["csrf_token"] = x.GetToken()
		ctx.Data["challenge"] = challenge
		ctx.Data["login_url"] = ctx.URLFor("consent_form")
		ctx.Data["client_id"] = clientId
		ctx.Data["client_name"] = resp.Client.Name
		ctx.Data["subject"] = subject
		ctx.Data["scopes"] = strings.Join(scopes, ",")
		ctx.Data["scope_labels"] = resp.RequestedScopes
		ctx.HTML(200, "consent")
	}
}

func ConsentPost(cfg *config.Config) CSRFHandler {
	return func(ctx *macaron.Context, x csrf.CSRF) {
		challenge := ctx.Query("challenge")
		clientId := ctx.Query("client_id")
		subject := ctx.Query("subject")
		scopes := strings.Split(ctx.Query("scopes"), ",")

		redirectURL := accept(ctx, cfg, clientId, subject, challenge, scopes)
		if redirectURL != "" {
			ctx.Redirect(redirectURL, http.StatusFound)
		}
	}
}

func accept(ctx *macaron.Context, cfg *config.Config, clientId, subject, challenge string, scopes []string) string {
	l := logging.FromMacaron(ctx)
	reqCtx := ctx.Req.Context()
	claims, err := cfg.Ldap.NewClientWithContext(reqCtx).
		WithAppId(clientId).
		FindOIDCClaims(subject)
	switch errors.Cause(err) {
	case nil:
		break
	case ldap.ErrUnauthorize:
		l.Debug().Str("challenge", challenge).Msg("unable to authorize during consent flow")
		ctx.Data["error"] = true
		ctx.Data["msg"] = fmt.Sprintf("user `%s` is not authorized to access this app", subject)
		ctx.HTML(http.StatusUnauthorized, "message")
		return ""
	default:
		l.Error().Err(err).Str("challenge", challenge).
			Msg("error fetching claim from ldap")
		ctx.Error(http.StatusInternalServerError, "internal server error")
		return ""
	}
	claims = hydra.FilterClaims(&cfg.Hydra, claims, scopes)

	remember := ctx.Query("rememberme") != ""
	redirectURL, err := hydra.AcceptConsentRequest(
		reqCtx,
		&cfg.Hydra,
		challenge,
		remember,
		scopes,
		claims,
	)
	if err != nil {
		l.Error().Str("challenge", challenge).Err(err).Msg("error making accept consent request against hydra ")
		ctx.Error(http.StatusInternalServerError, "internal server error")
	}
	return redirectURL
}
