package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/stregouet/hydra-ldap/internal/config"
	"github.com/stregouet/hydra-ldap/internal/logging"
	"github.com/stregouet/hydra-ldap/internal/oidc"
	"github.com/stregouet/hydra-ldap/internal/server"
)

func Execute() {
	var cfgFile string
	RootCmd := &cobra.Command{
		Use:   "hydra-ldap",
		Short: "identity provider for hydra based on ldap",
		Run: func(cmd *cobra.Command, args []string) {
			Run(cfgFile)
		},
	}
	RootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "Config file")

	if err := RootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}
}

func Run(cfgFile string) {
	var c config.Config
	initConfig(cfgFile, &c)
	if err := c.Validate(); err != nil {
		panic(fmt.Sprintf("error in config %v", err))
	}
	logging.Setup(&c.Log, c.Dev)
	if err := oidc.Setup(&c.SelfService); err != nil {
		panic(fmt.Sprintf("cannot setup oauth client %v", err))
	}
	server.Start(&c)
}

func initConfig(cfgFile string, c *config.Config) {
	if cfgFile != "" {
		fmt.Printf("set configfile %v\n", cfgFile)
		viper.SetConfigFile(cfgFile)
	}
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.AutomaticEnv() // read in environment variables that match
	if err := viper.ReadInConfig(); err != nil {
		fmt.Printf("Config file not found because `%s`\n", err)
	}

	err := viper.Unmarshal(&c)
	if err != nil {
		panic(fmt.Sprintf("unable to decode into struct, %v", err))
	}
}
