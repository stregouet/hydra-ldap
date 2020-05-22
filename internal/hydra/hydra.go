package hydra

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"

	"github.com/pkg/errors"
)

var (
	// ErrChallengeMissed is an error that happens when a challenge is missed.
	ErrChallengeMissed = errors.New("challenge missed")
	// ErrUnauthenticated is an error that happens when authentication is failed.
	ErrUnauthenticated = errors.New("unauthenticated")
	// ErrChallengeNotFound is an error that happens when an unknown challenge is used.
	ErrChallengeNotFound = errors.New("challenge not found")
	// ErrChallengeExpired is an error that happens when a challenge is already used.
	ErrChallengeExpired = errors.New("challenge expired")
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

func GetLoginRequest(cfg *Config, challenge string) (*HydraResp, error) {
	ref, err := url.Parse(fmt.Sprintf("oauth2/auth/requests/login?login_challenge=%s", challenge))
	if err != nil {
		return nil, err
	}
	u := cfg.ParsedUrl().ResolveReference(ref)
	resp, err := http.Get(u.String())

	if err != nil {
		return nil, errors.Wrap(err, "http request to hydra failed")
	}
	if err = checkResponse(resp); err != nil {
		return nil, errors.Wrap(err, "hydra reply with error")
	}
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Wrap(err, "read of response body failed")
	}
	var hr HydraResp
	if err := json.Unmarshal(data, &hr); err != nil {
		return nil, errors.Wrap(err, "parsing response body as json failed")
	}
	return &hr, nil
}

func AcceptLoginRequest(cfg *Config, remember bool, subject, challenge string) (string, error) {
	if challenge == "" {
		return "", ErrChallengeMissed
	}
	ref, err := url.Parse(fmt.Sprintf("oauth2/auth/requests/login/accept?login_challenge=%s", challenge))
	if err != nil {
		return "", errors.Wrap(err, "parsing url failed")
	}
	u := cfg.ParsedUrl().ResolveReference(ref)
	data := struct {
		Remember    bool   `json:"remember"`
		RememberFor int    `json:"remember_for"`
		Subject     string `json:"subject"`
	}{
		Remember:    remember,
		RememberFor: cfg.RememberFor(),
		Subject:     subject,
	}

	resp, err := putJSON(u, data)
	defer resp.Body.Close()
	if err := checkResponse(resp); err != nil {
		return "", errors.Wrap(err, "checking response status failed")
	}
	var rs struct {
		RedirectTo string `json:"redirect_to"`
	}
	dec := json.NewDecoder(resp.Body)
	if err := dec.Decode(&rs); err != nil {
		return "", errors.Wrap(err, "parse of response body failed")
	}
	return rs.RedirectTo, nil
}

func GetConsentRequest(cfg *Config, challenge string) (*HydraResp, error) {
	ref, err := url.Parse(fmt.Sprintf("oauth2/auth/requests/consent?consent_challenge=%s", challenge))
	if err != nil {
		return nil, err
	}
	u := cfg.ParsedUrl().ResolveReference(ref)
	resp, err := http.Get(u.String())

	if err != nil {
		return nil, errors.Wrap(err, "http request to hydra failed")
	}
	if err = checkResponse(resp); err != nil {
		return nil, errors.Wrap(err, "hydra reply with error")
	}
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Wrap(err, "read of response body failed")
	}
	var hr HydraResp
	if err := json.Unmarshal(data, &hr); err != nil {
		return nil, errors.Wrap(err, "parsing response body as json failed")
	}
	return &hr, nil
}

func AcceptConsentRequest(cfg *Config, challenge string, remember bool, grantScope []string, claims interface{}) (string, error) {
	type session struct {
		IDToken interface{} `json:"id_token,omitempty"`
	}
	data := struct {
		GrantScope  []string `json:"grant_scope"`
		Remember    bool     `json:"remember"`
		RememberFor int      `json:"remember_for"`
		Session     session  `json:"session,omitempty"`
	}{
		GrantScope:  grantScope,
		Remember:    remember,
		RememberFor: cfg.RememberFor(),
		Session: session{
			IDToken: claims,
		},
	}
	if challenge == "" {
		return "", ErrChallengeMissed
	}
	ref, err := url.Parse(fmt.Sprintf("oauth2/auth/requests/consent/accept?consent_challenge=%s", challenge))
	if err != nil {
		return "", errors.Wrap(err, "parsing url failed")
	}
	u := cfg.ParsedUrl().ResolveReference(ref)

	resp, err := putJSON(u, data)
	defer resp.Body.Close()
	if err := checkResponse(resp); err != nil {
		return "", errors.Wrap(err, "checking response status failed")
	}
	var rs struct {
		RedirectTo string `json:"redirect_to"`
	}
	dec := json.NewDecoder(resp.Body)
	if err := dec.Decode(&rs); err != nil {
		return "", errors.Wrap(err, "parse of response body failed")
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
		data, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		if err := json.Unmarshal(data, &rs); err != nil {
			return err
		}
		return fmt.Errorf("bad HTTP status code %d with message %q", resp.StatusCode, rs.Message)
	}
}
