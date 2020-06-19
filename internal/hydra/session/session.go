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

type ConsentReq struct {
	Client hydra.ClientInfo `json:client`
}

type ConsentSession struct {
	GrantScope     []string   `json:"grant_scope"`
	HandledAt      time.Time  `json:"handled_at"`
	ConsentRequest ConsentReq `json:"consent_request"`
}

func FetchConsentSessions(ctx context.Context, cfg *hydra.Config, subject string) ([]ConsentSession, error) {

	client := &hydra.HttpClient{cfg, ctx}

	urlPath := fmt.Sprintf("oauth2/auth/sessions/consent?subject=%s", url.QueryEscape(subject))
	ref, err := url.Parse(urlPath)
	if err != nil {
		return nil, err
	}
	fullUrl := client.Cfg.ParsedUrl().ResolveReference(ref)
	r, err := http.NewRequestWithContext(client.Ctx, http.MethodGet, fullUrl.String(), nil)
	if err != nil {
		return nil, errors.Wrap(err, "while building http request for hydra server")
	}

	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		return nil, errors.Wrap(err, "while requesting hydra server")
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("bad status code (%v) from hydra server", resp.StatusCode)
	}
	var sess []ConsentSession
	dec := json.NewDecoder(resp.Body)
	if err := dec.Decode(&sess); err != nil {
		return nil, errors.Wrap(err, "while parsing of response body from hydra server")
	}
	return Filter(sess), nil
}

func RevokeApp(ctx context.Context, cfg *hydra.Config, subject, clientid string) error {
	client := &hydra.HttpClient{cfg, ctx}

	urlPath := fmt.Sprintf("oauth2/auth/sessions/consent?subject=%s&client=%s",
		url.QueryEscape(subject),
		url.QueryEscape(clientid))
	ref, err := url.Parse(urlPath)
	if err != nil {
		return err
	}
	fullUrl := client.Cfg.ParsedUrl().ResolveReference(ref)
	r, err := http.NewRequestWithContext(client.Ctx, http.MethodDelete, fullUrl.String(), nil)
	if err != nil {
		return errors.Wrap(err, "while building http request for hydra server")
	}

	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		return errors.Wrap(err, "while requesting hydra server")
	}
	defer resp.Body.Close()
	if resp.StatusCode == 204 || resp.StatusCode == 201 {
		return nil
	}
	var jsonResp struct {
		Debug            string `json:debug`
		Error            string `json:error`
		ErrorDescription string `json:error_description`
	}
	dec := json.NewDecoder(resp.Body)
	if err := dec.Decode(&jsonResp); err != nil {
		return errors.Wrap(err, "while parsing of response body from hydra server")
	}
	logging.Error().Str("error", jsonResp.Error).Str("debug", jsonResp.Debug).Str("descr", jsonResp.ErrorDescription).Msg("hydra sent error")
	if jsonResp.Error != "" {
		return errors.New(jsonResp.Error)
	}

	return fmt.Errorf("something bad happened when trying to revoke access for %s", clientid)
}

func Logout(ctx context.Context, cfg *hydra.Config, subject string) error {
	client := &hydra.HttpClient{cfg, ctx}

	urlPath := fmt.Sprintf("oauth2/auth/sessions/login?subject=%s", url.QueryEscape(subject))
	ref, err := url.Parse(urlPath)
	if err != nil {
		return err
	}
	fullUrl := client.Cfg.ParsedUrl().ResolveReference(ref)
	r, err := http.NewRequestWithContext(client.Ctx, http.MethodDelete, fullUrl.String(), nil)
	if err != nil {
		return errors.Wrap(err, "while building http request for hydra server")
	}

	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		return errors.Wrap(err, "while requesting hydra server")
	}
	defer resp.Body.Close()
	if resp.StatusCode == 204 || resp.StatusCode == 201 {
		return nil
	}

	var jsonResp struct {
		Debug            string `json:debug`
		Error            string `json:error`
		ErrorDescription string `json:error_description`
	}
	dec := json.NewDecoder(resp.Body)
	if err := dec.Decode(&jsonResp); err != nil {
		return errors.Wrap(err, "while parsing of response body from hydra server")
	}
	logging.Error().Str("error", jsonResp.Error).Str("debug", jsonResp.Debug).Str("descr", jsonResp.ErrorDescription).Msg("hydra sent error")
	if jsonResp.Error != "" {
		return errors.New(jsonResp.Error)
	}

	return fmt.Errorf("something bad happened when trying to invalidate subject session %s", subject)
}
