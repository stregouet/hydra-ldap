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
  resp, err := getXRequest(cfg, fmt.Sprintf("oauth2/auth/requests/login?login_challenge=%s", challenge))
  if err != nil {
    return nil, err
  }
  return resp, nil
}

func AcceptLoginRequest(cfg *Config, remember bool, subject, challenge string) (string, error) {
	if challenge == "" {
		return "", ErrChallengeMissed
	}
	data := struct {
		Remember    bool   `json:"remember"`
		RememberFor int    `json:"remember_for"`
		Subject     string `json:"subject"`
	}{
		Remember:    remember,
		RememberFor: cfg.RememberFor(),
		Subject:     subject,
	}
  redirectURL, err := acceptXRequest(cfg, fmt.Sprintf("oauth2/auth/requests/login/accept?login_challenge=%s", challenge), data)
  if err != nil {
    return "", err
  }
  return redirectURL, nil
}

func GetConsentRequest(cfg *Config, challenge string) (*HydraResp, error) {
  resp, err := getXRequest(cfg, fmt.Sprintf("oauth2/auth/requests/consent?consent_challenge=%s", challenge))
  if err != nil {
    return nil, err
  }
  return resp, nil
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
  redirectURL, err := acceptXRequest(cfg, fmt.Sprintf("oauth2/auth/requests/consent/accept?consent_challenge=%s", challenge), data)
  if err != nil {
    return "", err
  }
  return redirectURL, nil
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
