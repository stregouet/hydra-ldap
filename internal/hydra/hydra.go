package hydra

import (
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

func GetLoginRequest(cfg *Config, challenge string) (*HydraResp, error) {
	resp, err := getRequest(cfg, &reqInfo{reqType: LOGIN_REQ, challenge: challenge})
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
	redirectURL, err := acceptRequest(cfg, &reqInfo{reqType: LOGIN_REQ, challenge: challenge}, data)
	if err != nil {
		return "", err
	}
	return redirectURL, nil
}

func GetConsentRequest(cfg *Config, challenge string) (*HydraResp, error) {
	resp, err := getRequest(cfg, &reqInfo{reqType: CONSENT_REQ, challenge: challenge})
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
	redirectURL, err := acceptRequest(cfg, &reqInfo{reqType: CONSENT_REQ, challenge: challenge}, data)
	if err != nil {
		return "", err
	}
	return redirectURL, nil
}

func FilterClaims(cfg *Config, claims map[string]string, requestedScopes []string) map[string]string {
	result := make(map[string]string, len(claims))
	// ignore error as it should alreay be handled in Validate
	scopeClaims, _ := cfg.ParsedClaimScopes()
	for _, scope := range requestedScopes {
		expectedClaims, ok := scopeClaims[scope]
		if !ok {
			continue
		}
		for _, expectedClaim := range expectedClaims {
			if value, ok := claims[expectedClaim]; ok {
				result[expectedClaim] = value
			}
		}
	}
	return result
}
