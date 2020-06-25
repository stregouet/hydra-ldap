package session

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/pkg/errors"

	"github.com/stregouet/hydra-ldap/internal/hydra"
	"github.com/stregouet/hydra-ldap/internal/logging"
)

type reqType int

type ConsentReq struct {
	Client hydra.ClientInfo `json:client`
}

type ConsentSession struct {
	GrantScope     []string   `json:"grant_scope"`
	HandledAt      time.Time  `json:"handled_at"`
	ConsentRequest ConsentReq `json:"consent_request"`
}

type reqInfo struct {
	reqType
	subject  string
	clientId string
}

const (
	DEL_LOGIN_REQ   reqType = 0
	DEL_CONSENT_REQ reqType = 1
	GET_CONSENT_REQ reqType = 2
)

func (r *reqInfo) ReqPath() string {
	if r.reqType == DEL_LOGIN_REQ {
		return "login"
	}
	if r.reqType == DEL_CONSENT_REQ {
		return "consent"
	}
	if r.reqType == GET_CONSENT_REQ {
		return "consent"
	}
	return ""
}

func call(c hydra.HttpClientInterface, info *reqInfo, jsonResp interface{}) error {
	l := logging.FromCtx(c.GetContext())
	urlPath := fmt.Sprintf("oauth2/auth/sessions/%[1]s", info.ReqPath())
	values := &url.Values{}
	if info.subject != "" {
		values.Set("subject", info.subject)
	}
	if info.clientId != "" {
		values.Set("client", info.clientId)
	}
	urlPath = fmt.Sprintf("%s?%s", urlPath, values.Encode())

	ref, err := url.Parse(urlPath)
	if err != nil {
		return errors.Wrap(err, "while parsing url")
	}
	var (
		resp    *http.Response
		httperr error
	)
	if info.reqType == GET_CONSENT_REQ {
		resp, httperr = c.Get(ref)
	} else {
		resp, httperr = c.Delete(ref)
	}
	if httperr != nil {
		return errors.Wrap(httperr, "http request to hydra failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		// error case, status code should be 2XX
		if err := hydra.GenericError(c.GetContext(), resp.Body); err != nil {
			return err
		}
		l.Debug().
			Int("statuscode", resp.StatusCode).
			Msgf("hydra sent error (reqinfo %#v)", info)
		return fmt.Errorf("hydra sent error with statuscode %v", resp.StatusCode)
	}
	if jsonResp != nil {
		dec := json.NewDecoder(resp.Body)
		if err := dec.Decode(jsonResp); err != nil {
			return errors.Wrap(err, "while parsing of response body from hydra server")
		}
	}
	return nil
}

func FetchConsentSessions(ctx context.Context, cfg *hydra.Config, subject string) ([]ConsentSession, error) {
	client := &hydra.HttpClient{cfg, ctx}
	var sess []ConsentSession
	err := call(client, &reqInfo{reqType: GET_CONSENT_REQ, subject: subject}, &sess)
	if err != nil {
		return nil, err
	}
	return Filter(sess), nil
}

func RevokeApp(ctx context.Context, cfg *hydra.Config, subject, clientid string) error {
	return call(
		&hydra.HttpClient{cfg, ctx},
		&reqInfo{reqType: DEL_CONSENT_REQ, subject: subject, clientId: clientid},
		nil,
	)
}

func Logout(ctx context.Context, cfg *hydra.Config, subject string) error {
	return call(
		&hydra.HttpClient{cfg, ctx},
		&reqInfo{reqType: DEL_LOGIN_REQ, subject: subject},
		nil,
	)
}
