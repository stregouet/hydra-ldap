package oidc

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"reflect"

	"github.com/go-macaron/session"
	"github.com/pkg/errors"
	"golang.org/x/oauth2"

	"github.com/stregouet/hydra-ldap/internal/logging"
)

const (
	clockSkew  = 10 * time.Second
	sessionKey = "oauth-session"
)

type Client struct {
	oauthCfg *oauth2.Config
	oidcCfg  *OpenIDConfig
	cfg      *Config
}

type OpenIDConfig struct {
	AuthEndpoint     string `json:"authorization_endpoint"`
	TokenEndpoint    string `json:"token_endpoint"`
	UserInfoEndpoint string `json:"userinfo_endpoint"`
	Issuer           string `json:"issuer"`
}

type OauthSession struct {
	State       string
	AccessToken string
	IDToken     string
}

var c Client

func Setup(cfg *Config) error {
	c = Client{cfg: cfg}
	if err := c.getOpenIDConfig(); err != nil {
		return err
	}
	c.oauthCfg = &oauth2.Config{
		ClientID:     c.cfg.ClientId,
		ClientSecret: c.cfg.Secret,
		RedirectURL:  c.cfg.CallbackUrl,
		Endpoint: oauth2.Endpoint{
			AuthURL:   c.oidcCfg.AuthEndpoint,
			TokenURL:  c.oidcCfg.TokenEndpoint,
			AuthStyle: oauth2.AuthStyleInParams,
		},
		Scopes: []string{"openid"},
	}
	return nil
}

func BeginAuthHandler(stateParam string, sess session.Store) (string, error) {
	state := setState(stateParam)
	url := c.oauthCfg.AuthCodeURL(state)
	if err := sess.Set(sessionKey, OauthSession{State: state}); err != nil {
		return "", errors.Wrap(err, "cannot store oauthsession in session")
	}
	return url, nil
}

func CompleteUserAuth(codeParam, stateParam string, sess session.Store) (map[string]interface{}, error) {
	oauthSess, ok := sess.Get(sessionKey).(OauthSession)
	if !ok {
		return nil, errors.New("cannot get oauthsession from session")
	}
	if err := validateState(stateParam, &oauthSess); err != nil {
		return nil, errors.Wrap(err, "cannot validate oauth state")
	}

	if err := authorize(codeParam, &oauthSess); err != nil {
		return nil, errors.Wrap(err, "cannot get access token")
	}
	return fetchClaims(&oauthSess)
}

func authorize(codeParam string, oauthSess *OauthSession) error {
	token, err := c.oauthCfg.Exchange(oauth2.NoContext, codeParam)
	if err != nil {
		return err
	}

	if !token.Valid() {
		return errors.New("Invalid token received from provider")
	}

	oauthSess.AccessToken = token.AccessToken
	oauthSess.IDToken = token.Extra("id_token").(string)
	return nil
}

func fetchClaims(oauthSess *OauthSession) (map[string]interface{}, error) {
	if oauthSess.IDToken == "" {
		return nil, errors.New(" cannot get user information without id_token")
	}
	// decode returned id token to get expiry
	claims, err := decodeJWT(oauthSess.IDToken)
	if err != nil {
		return nil, errors.Wrap(err, "oauth2, error while decoding jwt token")
	}

	if err := validateClaims(claims); err != nil {
		return nil, errors.Wrap(err, "oauth2, error while validating jwt token")
	}

	if err := getUserInfo(oauthSess.AccessToken, claims); err != nil {
		return nil, errors.Wrap(err, "oauth2, error while getting userinfo")
	}
	return claims, nil
}

func getUserInfo(accessToken string, claims map[string]interface{}) error {
	userInfoClaims, err := c.fetchUserInfo(accessToken)
	if err != nil {
		return err
	}

	// The sub (subject) Claim MUST always be returned in the UserInfo Response.
	// http://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse
	userInfoSubject := userInfoClaims["sub"].(string)
	if userInfoSubject == "" {
		logging.Debug().Str("claim", fmt.Sprintf("%#v", userInfoClaims)).Msg("userinfo response did not contain sub claim")
		return errors.New("userinfo response did not contain a 'sub' claim")
	}

	// The sub Claim in the UserInfo Response MUST be verified to exactly match the sub Claim in the ID Token;
	// if they do not match, the UserInfo Response values MUST NOT be used.
	// http://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse
	subject := claims["sub"].(string)
	if userInfoSubject != subject {
		logging.Debug().Str("id_token.subject", subject).Str("user_info.subject", userInfoSubject).
			Msg("userinfo `sub` claim did not match id_token `sub` claim")
		return errors.New("userinfo 'sub' claim did not match id_token 'sub' claim")
	}

	// Merge in userinfo claims in case id_token claims contained some that userinfo did not
	for k, v := range userInfoClaims {
		claims[k] = v
	}

	return nil
}

func validateState(stateParam string, oauthSess *OauthSession) error {
	origState := oauthSess.State
	if origState != "" && (origState != stateParam) {
		return errors.New("state token mismatch")
	}
	return nil
}

func setState(stateParam string) string {
	if len(stateParam) > 0 {
		return stateParam
	}

	// If a state query param is not passed in, generate a random
	// base64-encoded nonce so that the state on the auth URL
	// is unguessable, preventing CSRF attacks, as described in
	//
	// https://auth0.com/docs/protocols/oauth2/oauth-state#keep-reading
	nonceBytes := make([]byte, 64)
	_, err := io.ReadFull(rand.Reader, nonceBytes)
	if err != nil {
		panic("source of randomness unavailable: " + err.Error())
	}
	return base64.URLEncoding.EncodeToString(nonceBytes)
}

func (c *Client) getOpenIDConfig() error {
	res, err := http.Get(c.cfg.DiscoveryUrl)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return err
	}

	openIDConfig := &OpenIDConfig{}
	err = json.Unmarshal(body, openIDConfig)
	if err != nil {
		return err
	}

	c.oidcCfg = openIDConfig
	return nil
}

// fetch and decode JSON from the given UserInfo URL
func (c *Client) fetchUserInfo(accessToken string) (map[string]interface{}, error) {
	req, _ := http.NewRequest("GET", c.oidcCfg.UserInfoEndpoint, nil)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Non-200 response from UserInfo: %d, WWW-Authenticate=%s", resp.StatusCode, resp.Header.Get("WWW-Authenticate"))
	}

	// The UserInfo Claims MUST be returned as the members of a JSON object
	// http://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return unMarshal(data)
}

// validate according to standard, returns expiry
// http://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation
func validateClaims(claims map[string]interface{}) error {
	// TODO test à tester avec claims[aud] une string ou une liste de string
	switch v := claims["aud"].(type) {
	case string:
		if v != c.cfg.ClientId {
			logging.Error().Str("token_id.aud", v).Str("clientId", c.cfg.ClientId).Msg("mismatch audience")
			return errors.New("audience in token does not match client key")
		}
	case []interface{}:
		found := false
		dbg := make([]string, len(v))
		for _, tokenIdAud := range v {
			if tokenIdAud == c.cfg.ClientId {
				found = true
				break
			} else {
				dbg = append(dbg, tokenIdAud.(string))
			}
		}
		if !found {
			logging.Error().Strs("token_id.aud", dbg).Str("clientId", c.cfg.ClientId).Msg("mismatch audience")
			return errors.New("audience in token does not match client key")
		}
	default:
		logging.Error().Str("token_id.aud.kind", reflect.ValueOf(claims["aud"]).Kind().String()).Msg("bad value in token_id.aud")
		return errors.New("audience in token does not match client key")
	}

	if claims["iss"] != c.oidcCfg.Issuer {
		return errors.New("issuer in token does not match issuer in OpenIDConfig discovery")
	}

	// expiry is required for JWT, not for UserInfoResponse
	// is actually a int64, so force it in to that type
	expiryClaim := int64(claims["exp"].(float64))
	expiry := time.Unix(expiryClaim, 0)
	if expiry.Add(clockSkew).Before(time.Now()) {
		return errors.New("user info JWT token is expired")
	}
	return nil
}

// decodeJWT decodes a JSON Web Token into a simple map
// http://openid.net/specs/draft-jones-json-web-token-07.html
func decodeJWT(jwt string) (map[string]interface{}, error) {
	jwtParts := strings.Split(jwt, ".")
	if len(jwtParts) != 3 {
		return nil, errors.New("jws: invalid token received, not all parts available")
	}

	decodedPayload, err := base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString(jwtParts[1])

	if err != nil {
		return nil, err
	}

	return unMarshal(decodedPayload)
}

func unMarshal(payload []byte) (map[string]interface{}, error) {
	data := make(map[string]interface{})

	return data, json.NewDecoder(bytes.NewBuffer(payload)).Decode(&data)
}
