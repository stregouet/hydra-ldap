package hydra

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/pkg/errors"
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

type httpClient struct {
	cfg *Config
}

type httpClientInterface interface {
	putJSON(u *url.URL, body io.Reader) (*http.Response, error)
	get(u *url.URL) (*http.Response, error)
}

func (client *httpClient) get(u *url.URL) (*http.Response, error) {
	fullUrl := client.cfg.ParsedUrl().ResolveReference(u)
	return http.Get(fullUrl.String())
}

func (client *httpClient) putJSON(u *url.URL, body io.Reader) (*http.Response, error) {
	fullUrl := client.cfg.ParsedUrl().ResolveReference(u)
	r, err := http.NewRequest(http.MethodPut, fullUrl.String(), body)
	if err != nil {
		return nil, err
	}
	r.Header.Set("Content-Type", "application/json")
	return http.DefaultClient.Do(r)
}

func call(c httpClientInterface, info *reqInfo, jsonReq interface{}, jsonResp interface{}) error {
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
		resp, httperr = c.putJSON(ref, buf)
	} else {
		resp, httperr = c.get(ref)
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

func getRequest(cfg *Config, info *reqInfo) (*HydraResp, error) {
	var hr HydraResp
	client := &httpClient{cfg}
	info.reqVerb = GET_VERB
	if err := call(client, info, nil, &hr); err != nil {
		return nil, err
	}
	return &hr, nil
}

func acceptRequest(cfg *Config, info *reqInfo, data interface{}) (string, error) {
	var rs struct {
		RedirectTo string `json:"redirect_to"`
	}
	client := &httpClient{cfg}
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
