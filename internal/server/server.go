package server

import (
	"io"
	"log"
	"log/syslog"
	"net/http"
	"os"

	"github.com/go-macaron/csrf"
	"github.com/go-macaron/session"
	"github.com/pkg/errors"
	"gopkg.in/macaron.v1"

	"github.com/stregouet/hydra-ldap/internal/config"
	"github.com/stregouet/hydra-ldap/internal/hydra"
	"github.com/stregouet/hydra-ldap/internal/ldap"
)

func Start(cfg *config.Config) {
	macaronEnv := ""
	if !cfg.Dev {
		macaronEnv = "production"
	}
	os.Setenv("MACARON_ENV", macaronEnv)
	m := macaron.NewWithLogger(createLogger(cfg))

	log.Printf("type m %#v", m)
	setupMiddlewares(m)
	setupRoutes(m, cfg)
	m.Map(&cfg.Ldap)
	m.Run()
}

func createLogger(cfg *config.Config) io.Writer {
	writers := []io.Writer{os.Stdout}
	if !cfg.Dev {
		syslogout, err := syslog.New(syslog.LOG_WARNING|syslog.LOG_DAEMON, "")
		if err != nil {
			log.Fatalf("unable to create syslog connection, %v", err)
		}
		writers = append(writers, syslogout)
	}
	return io.MultiWriter(writers...)
}

func setupMiddlewares(m *macaron.Macaron) {
	m.Use(macaron.Logger())
	m.Use(macaron.Recovery())
	m.Use(macaron.Static("public"))
	m.Use(macaron.Renderer())
	m.Use(session.Sessioner())
	m.Use(csrf.Csrfer())
}

func setupRoutes(m *macaron.Macaron, cfg *config.Config) {
	m.Combo("/auth/login").Get(func(ctx *macaron.Context, x csrf.CSRF, logger *log.Logger) {
		challenge := ctx.Query("login_challenge")
		if challenge == "" {
			ctx.Error(http.StatusBadRequest, "missing login challenge")
			return
		}
		resp, err := hydra.GetLoginRequest(&cfg.Hydra, challenge)
		switch errors.Cause(err) {
		case nil:
			break
		case hydra.ErrChallengeNotFound:
			logger.Printf("DEBUG Unknown login challenge in the OAuth2 provider %v (challenge: %q)", err, challenge)
			ctx.Error(http.StatusBadRequest, "unknown login challenge")
			return
		case hydra.ErrChallengeExpired:
			logger.Printf("DEBUG Login challenge has been used already in the OAuth2 provider %v (challenge: %q)", err, challenge)
			ctx.Error(http.StatusBadRequest, "Login challenge has been used already")
			return
		default:
			logger.Printf("DEBUG Failed to initiate an OAuth2 login request %v (challenge: %q)", err, challenge)
			ctx.Error(http.StatusInternalServerError, "internal server error")
			return
		}
		// TODO if resp.Skip

		ctx.Data["Title"] = "login-sso"
		ctx.Data["csrf_token"] = x.GetToken()
		ctx.Data["challenge"] = challenge
		ctx.Data["login_url"] = ctx.URLFor("login_form")
		ctx.Data["client_id"] = resp.Client.Id
		ctx.Data["client_name"] = resp.Client.Name
		ctx.HTML(200, "login")
	}).Post(csrf.Validate, func(ctx *macaron.Context, x csrf.CSRF, logger *log.Logger, ldapcfg *ldap.Config) {
		challenge := ctx.Query("challenge")
		username := ctx.Query("username")
		password := ctx.Query("password")
		clientId := ctx.Query("client_id")
		clientName := ctx.Query("client_name")

		if challenge == "" {
			logger.Printf("No login challenge that is needed by the OAuth2 provider")
			ctx.Error(http.StatusBadRequest, "unknown login challenge")
			return
		}

		ctx.Data["Title"] = "login-sso"
		ctx.Data["csrf_token"] = x.GetToken()
		ctx.Data["challenge"] = challenge
		ctx.Data["login_url"] = ctx.URLFor("login_form")
		ctx.Data["client_id"] = clientId
		ctx.Data["client_name"] = clientName

		switch ok, err := ldapcfg.IsAuthorized(ctx.Req.Context(), username, password); {
		case err != nil:
			logger.Printf("DEBUG error trying to authentificate %v (challenge: %q)", err, challenge)
			ctx.Data["error"] = true
			ctx.Data["msg"] = err.Error()
			ctx.HTML(http.StatusInternalServerError, "login")
		case !ok:
			logger.Printf("DEBUG unable to authentificate (challenge: %q)", challenge)
			ctx.Data["error"] = true
			ctx.Data["msg"] = "bad username or password"
			ctx.HTML(http.StatusUnauthorized, "login")
			return
		}
		remember := ctx.Query("remember") != ""
		// XXX `subject` parameter could be either email or uid is this a problem?
		redirectURL, err := hydra.AcceptLoginRequest(&cfg.Hydra, remember, username, challenge)
		if err != nil {
			logger.Printf("DEBUG error making accept login request against hydra %v (challenge: %q)", err, challenge)
			ctx.Data["error"] = true
			ctx.Data["msg"] = err.Error()
			ctx.HTML(http.StatusInternalServerError, "login")
			return
		}

		ctx.Redirect(redirectURL, http.StatusFound)
	}).Name("login_form")

	m.Combo("/auth/consent").Get(func(ctx *macaron.Context, logger *log.Logger, ldapcfg *ldap.Config) {
		challenge := ctx.Query("consent_challenge")
		if challenge == "" {
			logger.Printf("No consent challenge that is needed by the OAuth2 provider")
			ctx.Error(http.StatusBadRequest, "unknown consent challenge")
			return
		}

		resp, err := hydra.GetConsentRequest(&cfg.Hydra, challenge)
		switch errors.Cause(err) {
		case nil:
			break
		case hydra.ErrChallengeNotFound:
			logger.Printf("DEBUG Unknown login challenge in the OAuth2 provider %v (challenge: %q)", err, challenge)
			ctx.Error(http.StatusBadRequest, "unknown login challenge")
			return
		case hydra.ErrChallengeExpired:
			logger.Printf("DEBUG Login challenge has been used already in the OAuth2 provider %v (challenge: %q)", err, challenge)
			ctx.Error(http.StatusBadRequest, "Login challenge has been used already")
			return
		default:
			logger.Printf("DEBUG Failed to initiate an OAuth2 login request %v (challenge: %q)", err, challenge)
			ctx.Error(http.StatusInternalServerError, "internal server error")
			return
		}
		claims, err := ldapcfg.FindOIDCClaims(ctx.Req.Context(), resp.Subject)
		redirectURL, err := hydra.AcceptConsentRequest(&cfg.Hydra, challenge, !resp.Skip, resp.RequestedScopes, claims)
		if err != nil {
			logger.Printf("DEBUG error making accept consent request against hydra %v (challenge: %q)", err, challenge)
			ctx.Error(http.StatusInternalServerError, "internal server error")
		}
		ctx.Redirect(redirectURL, http.StatusFound)
	}).Name("consent_form")

}
