package oidc

import (
	"github.com/stregouet/hydra-ldap/internal/types"
)

type Config struct {
	ClientId     string
	Secret       string
	DiscoveryUrl string
	CallbackUrl  string
}

func (c *Config) Validate() error {
	return nil
}

func (cfg *Config) GetDefaults() []types.Default {
	return []types.Default{}
}
