package config

import (
	"github.com/stregouet/hydra-ldap/internal/hydra"
	"github.com/stregouet/hydra-ldap/internal/ldap"
	"github.com/stregouet/hydra-ldap/internal/logging"
	"github.com/stregouet/hydra-ldap/internal/oidc"
)

type Config struct {
	Dev         bool
	Listen      string
	Hydra       hydra.Config
	Ldap        ldap.Config
	Log         logging.Config
	SelfService oidc.Config
}

func (cfg *Config) Validate() error {
	if err := cfg.Hydra.Validate(); err != nil {
		return err
	}
	if err := cfg.Ldap.Validate(); err != nil {
		return err
	}
	if err := cfg.Log.Validate(); err != nil {
		return err
	}
	if err := cfg.SelfService.Validate(); err != nil {
		return err
	}
	return nil
}
