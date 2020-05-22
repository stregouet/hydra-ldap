package cmd

import (
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/stregouet/hydra-ldap/internal/config"
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
		log.Fatalf("unable to decode into struct, %v", err)
	}
}
