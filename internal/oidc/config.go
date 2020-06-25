package oidc

type Config struct {
	ClientId     string
	Secret       string
	DiscoveryUrl string
	CallbackUrl  string
}

func (c *Config) Validate() error {
	return nil
}
