package main

import (
	"fmt"

	"github.com/spf13/viper"
)

func initConfig() {

	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")

	err := viper.ReadInConfig()
	if err != nil {
		panic(fmt.Errorf("Fatal error config file: %s \n", err))
	}

	viper.SetDefault("scanner.clair.url", "http://localhost:6060")
	viper.SetDefault("scanner.trivy.url", "http://localhost:6061")
	viper.SetDefault("reporter.elasticsearch.url", "http://localhost:9200")
}
