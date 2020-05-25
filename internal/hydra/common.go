package hydra

import (
  "encoding/json"
  "io/ioutil"
  "net/http"
  "net/url"

  "github.com/pkg/errors"
)

func getXRequest(cfg *Config, urlPath string) (*HydraResp, error) {
	ref, err := url.Parse(urlPath)
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

func acceptXRequest(cfg *Config, urlPath string, data interface{}) (string, error) {
	ref, err := url.Parse(fmt.Sprintf("oauth2/auth/requests/login/accept?login_challenge=%s", challenge))
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
