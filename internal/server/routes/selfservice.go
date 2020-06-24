package routes

import (
	"net/http"

	"github.com/go-macaron/csrf"
	"github.com/go-macaron/session"
	"gopkg.in/macaron.v1"

	"github.com/stregouet/hydra-ldap/internal/config"
	hydraSess "github.com/stregouet/hydra-ldap/internal/hydra/session"
	"github.com/stregouet/hydra-ldap/internal/oidc"
)

func SelfService(cfg *config.Config) func(ctx *macaron.Context, sess session.Store, x csrf.CSRF) {
	return func(ctx *macaron.Context, sess session.Store, x csrf.CSRF) {
		l := fromReq(ctx)
		ctx.Data["Title"] = "login-sso"
		user := sess.Get("user")
		if user != nil {
			subject := user.(string)
			ctx.Data["user"] = subject
			consentSess, err := hydraSess.FetchConsentSessions(ctx.Req.Context(), &cfg.Hydra, subject)
			if err != nil {
				l.Error().Err(err).Msg("while trying to get sessions from hydra")
				ctx.Data["msg"] = "error while trying to get sessions from hydra"
				ctx.Data["error"] = true
			} else {
				ctx.Data["sessions"] = consentSess
				ctx.Data["csrf_token"] = x.GetToken()
			}
		}
		ctx.HTML(200, "dashboard")
	}
}

func SelfServiceLogin(cfg *config.Config) func(ctx *macaron.Context, sess session.Store) {
	return func(ctx *macaron.Context, sess session.Store) {
		l := fromReq(ctx)
		url, err := oidc.BeginAuthHandler(ctx.Query("state"), sess)
		if err != nil {
			l.Error().Err(err).Msg("cannot start oauth process")
			ctx.Error(http.StatusInternalServerError, "internal server error")
			return
		}
		ctx.Redirect(url, http.StatusFound)
	}
}

func SelfServiceLogout(cfg *config.Config) func(ctx *macaron.Context, sess session.Store) {
	return func(ctx *macaron.Context, sess session.Store) {
		l := fromReq(ctx)
		user := sess.Get("user")
		if user != nil {
			subject := user.(string)
			err := hydraSess.Logout(ctx.Req.Context(), &cfg.Hydra, subject)
			if err != nil {
				l.Error().Err(err).Msg("while trying to invalidate user's hydra session")
				ctx.Error(http.StatusInternalServerError, "internal server error")
				return
			}
			if err := sess.Delete("user"); err != nil {
				l.Error().Err(err).Msg("while trying to delete `user` from session")
				ctx.Error(http.StatusInternalServerError, "internal server error")
				return
			}
		}
		ctx.Redirect("/", http.StatusSeeOther)
	}

}

func SelfServiceOauth(cfg *config.Config) func(ctx *macaron.Context, sess session.Store) {
	return func(ctx *macaron.Context, sess session.Store) {
		l := fromReq(ctx)
		claims, err := oidc.CompleteUserAuth(ctx.Query("code"), ctx.Query("state"), sess)
		if err != nil {
			l.Error().Err(err).Msg("cannot complete auth user")
			ctx.Error(http.StatusInternalServerError, "internal server error")
			return
		}
		sess.Set("user", claims["sub"])
		ctx.Redirect("/", http.StatusSeeOther)
	}
}

func SelfServiceRevoke(cfg *config.Config) func(ctx *macaron.Context, x csrf.CSRF, sess session.Store) {
	return func(ctx *macaron.Context, x csrf.CSRF, sess session.Store) {
		l := fromReq(ctx)
		ctx.Data["Title"] = "login-sso"
		user := sess.Get("user")
		if user != nil {
			subject := user.(string)
			err := hydraSess.RevokeApp(ctx.Req.Context(), &cfg.Hydra, subject, ctx.Params(":clientid"))
			if err != nil {
				l.Error().Err(err).Msg("while trying to get sessions from hydra")
				ctx.Error(http.StatusInternalServerError, "internal server error")
				return
			}
		}
		ctx.Redirect("/", http.StatusSeeOther)
	}
}
