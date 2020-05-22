package hydra

import (
  "bytes"
  "encoding/json"
  "net/http"
  "net/url"
)


func putJSON(u *url.URL, body interface{}) (resp *http.Response, err error) {
	var content []byte
	if body != nil {
		if content, err = json.Marshal(body); err != nil {
			return nil, err
		}
	}

	r, err := http.NewRequest(http.MethodPut, u.String(), bytes.NewBuffer(content))
	if err != nil {
		return nil, err
	}
	r.Header.Set("Content-Type", "application/json")
	resp, err = http.DefaultClient.Do(r)
  return resp, err
}
