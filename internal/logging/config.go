package logging

import (
	"github.com/rs/zerolog"

	"github.com/stregouet/hydra-ldap/internal/types"
)

type Config struct {
	UseSystemd bool
	Level      string
}

func toZerologLvl(level string) zerolog.Level {
	// discard error since it was alrealy handle in validate
	lvl, _ := zerolog.ParseLevel(level)
	return lvl
}

func (cfg *Config) Validate() error {
	_, err := zerolog.ParseLevel(cfg.Level)
	if err != nil {
		return err
	}
	return nil
}

func (cfg *Config) GetDefaults() []types.Default {
	return []types.Default{
		types.Default{"usesystemd", false},
		types.Default{"level", "info"},
	}
}
