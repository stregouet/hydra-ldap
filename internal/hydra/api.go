package hydra

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/pkg/errors"
	"github.com/rs/zerolog"

	"github.com/stregouet/hydra-ldap/internal/logging"
)

type ClientInfo struct {
	Id   string `json:"client_id"`
	Name string `json:"client_name"`
}

// HydraResp contains response from Hydra
type HydraResp struct {
	Challenge       string     `json:"challenge"`
	RequestedScopes []string   `json:"requested_scope"`
	Skip            bool       `json:"skip"`
	Subject         string     `json:"subject"`
	Client          ClientInfo `json:"client"`
}

type reqType string
type reqVerb string

const (
	LOGIN_REQ   reqType = "login"
	CONSENT_REQ reqType = "consent"
)

const (
	ACCEPT_VERB reqVerb = "/accept"
	GET_VERB    reqVerb = ""
)

type reqInfo struct {
	reqType
	reqVerb
	challenge string
}

type HttpClient struct {
	Cfg *Config
	Ctx context.Context
}

type HttpClientInterface interface {
	PutJSON(u *url.URL, body io.Reader) (*http.Response, error)
	Get(u *url.URL) (*http.Response, error)
	GetContext() context.Context
}

func (client *HttpClient) GetContext() context.Context {
	return client.Ctx
}

func (client *HttpClient) Get(u *url.URL) (*http.Response, error) {
	fullUrl := client.Cfg.ParsedUrl().ResolveReference(u)
	r, err := http.NewRequestWithContext(client.GetContext(), http.MethodGet, fullUrl.String(), nil)
	if err != nil {
		return nil, err
	}

	return http.DefaultClient.Do(r)
}

func (client *HttpClient) PutJSON(u *url.URL, body io.Reader) (*http.Response, error) {
	fullUrl := client.Cfg.ParsedUrl().ResolveReference(u)
	r, err := http.NewRequestWithContext(client.GetContext(), http.MethodPut, fullUrl.String(), body)
	if err != nil {
		return nil, err
	}
	r.Header.Set("Content-Type", "application/json")
	return http.DefaultClient.Do(r)
}

func call(c HttpClientInterface, info *reqInfo, jsonReq interface{}, jsonResp interface{}) error {
	urlPath := fmt.Sprintf("oauth2/auth/requests/%[1]s%[2]s?%[1]s_challenge=%[3]s",
		info.reqType,
		info.reqVerb,
		info.challenge,
	)
	ref, err := url.Parse(urlPath)
	if err != nil {
		return err
	}
	var (
		resp    *http.Response
		httperr error
	)
	if jsonReq != nil {
		buf := new(bytes.Buffer)
		if err := json.NewEncoder(buf).Encode(jsonReq); err != nil {
			return err
		}
		if logging.Logger.GetLevel() <= zerolog.DebugLevel {
			// convert buf into string only if necessary
			logging.Debug().Str("data", buf.String()).Str("url", urlPath).Msg("will call hydra server")
		}
		resp, httperr = c.PutJSON(ref, buf)
	} else {
		logging.Debug().Str("url", urlPath).Msg("will call hydra server")
		resp, httperr = c.Get(ref)
	}

	defer resp.Body.Close()
	if httperr != nil {
		return errors.Wrap(httperr, "http request to hydra failed")
	}
	if err = checkResponse(resp); err != nil {
		return errors.Wrap(err, "hydra reply with error")
	}
	dec := json.NewDecoder(resp.Body)
	if err := dec.Decode(jsonResp); err != nil {
		return errors.Wrap(err, "parse of response body failed")
	}
	return nil
}

func getRequest(ctx context.Context, cfg *Config, info *reqInfo) (*HydraResp, error) {
	var hr HydraResp
	client := &HttpClient{cfg, ctx}
	info.reqVerb = GET_VERB
	if err := call(client, info, nil, &hr); err != nil {
		return nil, err
	}
	return &hr, nil
}

func acceptRequest(ctx context.Context, cfg *Config, info *reqInfo, data interface{}) (string, error) {
	var rs struct {
		RedirectTo string `json:"redirect_to"`
	}
	client := &HttpClient{cfg, ctx}
	info.reqVerb = ACCEPT_VERB
	if err := call(client, info, data, &rs); err != nil {
		return "", err
	}
	return rs.RedirectTo, nil
}

func checkResponse(resp *http.Response) error {
	if resp.StatusCode >= 200 && resp.StatusCode <= 302 {
		return nil
	}

	switch resp.StatusCode {
	case 401:
		return ErrUnauthenticated
	case 404:
		return ErrChallengeNotFound
	case 409:
		return ErrChallengeExpired
	default:
		var rs struct {
			Message string `json:"error"`
		}
		dec := json.NewDecoder(resp.Body)
		if err := dec.Decode(&rs); err != nil {
			return errors.Wrap(err, "parse of response body failed")
		}
		return fmt.Errorf("bad HTTP status code %d with message %q", resp.StatusCode, rs.Message)
	}
}
