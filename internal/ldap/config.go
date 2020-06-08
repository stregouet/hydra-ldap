package ldap

import (
	"strings"
)

type Config struct {
	Tls      bool
	Endpoint string
	Basedn   string

	Admindn string
	Adminpw string

	Attrs []string
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
	return nil
}
