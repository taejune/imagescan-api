package main

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"github.com/spf13/viper"
	"go.uber.org/zap"

	"github.com/taejune/imagescan-api/api"
)

func init() {

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

func main() {

	logger := zap.NewExample()
	defer logger.Sync()

	sugar := logger.Sugar()

	sugar.Info("Start ImageScanAPI server...")

	r := mux.NewRouter()
	r.HandleFunc("/health", HealthHandler)
	r.HandleFunc("/registry/catalog", api.Catalog)
	r.HandleFunc("/image/digest", api.Digest)
	r.HandleFunc("/image/scan", api.Scan)
	r.HandleFunc("/image/manifest", api.Manifest)
	r.HandleFunc("/image/layer", api.Layer)

	s := &http.Server{
		Addr:           ":8080",
		Handler:        r,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}

	sugar.Info("Listening on :8080")
	sugar.Fatal(s.ListenAndServe())
}

func HealthHandler(w http.ResponseWriter, r *http.Request) {

	log.Println("/health: Got request")

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}
