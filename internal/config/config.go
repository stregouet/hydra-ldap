package config

import (
	"fmt"

	"github.com/stregouet/hydra-ldap/internal/hydra"
	"github.com/stregouet/hydra-ldap/internal/ldap"
	"github.com/stregouet/hydra-ldap/internal/logging"
	"github.com/stregouet/hydra-ldap/internal/oidc"
	"github.com/stregouet/hydra-ldap/internal/types"
)

type Config struct {
	Dev    bool
	Server struct {
		Host string
		Port int
	}
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

func (cfg *Config) GetDefaults() []types.Default {
	defaults := []types.Default{
		types.Default{"server.host", "localhost"},
		types.Default{"server.port", 8080},
		types.Default{"dev", false},
	}
	for _, d := range cfg.Hydra.GetDefaults() {
		defaults = append(defaults, types.Default{
			fmt.Sprintf("hydra.%s", d.Key), d.Value,
		})
	}
	for _, d := range cfg.Ldap.GetDefaults() {
		defaults = append(defaults, types.Default{
			fmt.Sprintf("ldap.%s", d.Key), d.Value,
		})
	}
	for _, d := range cfg.Log.GetDefaults() {
		defaults = append(defaults, types.Default{
			fmt.Sprintf("log.%s", d.Key), d.Value,
		})
	}
	for _, d := range cfg.SelfService.GetDefaults() {
		defaults = append(defaults, types.Default{
			fmt.Sprintf("selfservice.%s", d.Key), d.Value,
		})
	}
	return defaults
}
