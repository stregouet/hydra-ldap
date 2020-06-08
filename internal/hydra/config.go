package hydra

import (
	"fmt"
	"net/url"
	"strings"
	"time"
)

type Config struct {
	Url         string
	SessionTTL  time.Duration
	ClaimScopes []string
}

func (c *Config) ParsedUrl() *url.URL {
	if res, err := url.Parse(c.Url); err != nil {
		panic("cannot parse hydra parse url")
	} else {
		return res
	}
}

func (c *Config) RememberFor() int {
	return int(c.SessionTTL.Seconds())
}

func (c *Config) Validate() error {
	if c.Url == "" {
		return fmt.Errorf("empty hydra url")
	}
	if !strings.HasSuffix(c.Url, "/") {
		c.Url += "/"
	}
	c.ParsedUrl()
	return nil
}
