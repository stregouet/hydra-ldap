package hydra

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/pkg/errors"
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

func (c *Config) ParsedClaimScopes() (map[string][]string, error) {
	result := make(map[string][]string)
	for _, claimScope := range c.ClaimScopes {
		splitted := strings.Split(claimScope, ":")
		if len(splitted) != 2 {
			return nil, fmt.Errorf(
				"one claim scope is not well formatted %#v (should contain exactly one `:`)",
				claimScope)
		}
		claim, scope := splitted[0], splitted[1]
		result[scope] = append(result[scope], claim)
	}
	return result, nil
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
	if _, err := c.ParsedClaimScopes(); err != nil {
		return errors.Wrap(err, "while validating Hydra.Config")
	}
	return nil
}
