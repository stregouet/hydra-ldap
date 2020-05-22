package config

import (
	"github.com/stregouet/hydra-ldap/internal/hydra"
	"github.com/stregouet/hydra-ldap/internal/ldap"
)

type Config struct {
	Dev    bool
	Listen string
	Hydra  hydra.Config
	Ldap   ldap.Config
}
