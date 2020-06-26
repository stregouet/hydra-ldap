package ldap

import (
	"fmt"
	"strings"

	"github.com/stregouet/hydra-ldap/internal/types"
)

type Config struct {
	Tls        bool
	Endpoint   string
	Basedn     string
	RoleBaseDN string

	Admindn string
	Adminpw string

	Attrs []string
}

func (cfg *Config) GetDefaults() []types.Default {
	return []types.Default{
		types.Default{"tls", false},
		types.Default{"attrs", []string{
			"name:name",
			"sn:family_name",
			"givenName:given_name",
			"mail:email",
		}},
	}
}

func (c *Config) attrsMap() map[string]string {
	result := make(map[string]string)
	for _, attr := range c.Attrs {
		parts := strings.SplitN(attr, ":", 2)
		if len(parts) != 2 {
			panic("attrsMap expects list of `:` separated strings")
		}
		result[parts[0]] = parts[1]
	}
	return result
}

func (cfg *Config) Validate() error {
	if cfg.Endpoint == "" {
		return fmt.Errorf("empty ldap endpoint")
	}
	if cfg.Basedn == "" {
		return fmt.Errorf("empty ldap basedn")
	}
	return nil
}
