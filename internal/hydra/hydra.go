package hydra

import (
	"context"

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

type Claim struct {
	Details map[string]string
	Roles   []string
}

func (c *Claim) prepareMarshal() map[string]interface{} {
	result := make(map[string]interface{}, len(c.Details)+1)
	for k, v := range c.Details {
		result[k] = v
	}
	if c.Roles != nil {
		result["roles"] = c.Roles
	}
	return result
}

func GetLoginRequest(ctx context.Context, cfg *Config, challenge string) (*HydraResp, error) {
	resp, err := getRequest(ctx, cfg, &reqInfo{reqType: LOGIN_REQ, challenge: challenge})
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func AcceptLoginRequest(ctx context.Context, cfg *Config, remember bool, subject, challenge string) (string, error) {
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
	redirectURL, err := acceptRequest(ctx, cfg, &reqInfo{reqType: LOGIN_REQ, challenge: challenge}, data)
	if err != nil {
		return "", err
	}
	return redirectURL, nil
}

func GetConsentRequest(ctx context.Context, cfg *Config, challenge string) (*HydraResp, error) {
	resp, err := getRequest(ctx, cfg, &reqInfo{reqType: CONSENT_REQ, challenge: challenge})
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func AcceptConsentRequest(ctx context.Context, cfg *Config, challenge string, remember bool, grantScope []string, claims *Claim) (string, error) {
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
			IDToken: claims.prepareMarshal(),
		},
	}
	if challenge == "" {
		return "", ErrChallengeMissed
	}
	redirectURL, err := acceptRequest(ctx, cfg, &reqInfo{reqType: CONSENT_REQ, challenge: challenge}, data)
	if err != nil {
		return "", err
	}
	return redirectURL, nil
}

func FilterClaims(cfg *Config, claims *Claim, requestedScopes []string) *Claim {
	result := &Claim{
		Details: make(map[string]string, len(claims.Details)),
	}
	// ignore error as it should alreay be handled in Validate
	scopeClaims, _ := cfg.ParsedClaimScopes()
	for _, scope := range requestedScopes {
		expectedClaims, ok := scopeClaims[scope]
		if !ok {
			continue
		}
		for _, expectedClaim := range expectedClaims {
			if value, ok := claims.Details[expectedClaim]; ok {
				result.Details[expectedClaim] = value
			}
		}
	}
	return result
}
