package main

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"time"

	"github.com/genuinetools/reg/clair"
	"github.com/gorilla/mux"
	"github.com/spf13/viper"
	"go.uber.org/zap"

	"github.com/taejune/imagescan-api/api"
	"github.com/taejune/imagescan-api/store"
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

	logger := zap.NewExample().Sugar()
	defer logger.Sync()

	// TODO: Support trivy
	scanner, _ := clair.New(viper.GetString("scanner.clair.url"), clair.Opt{
		Debug:    true,
		Insecure: false,
		Timeout:  time.Second * 3,
	})
	// TODO: Support other storage
	store := store.NewStore(viper.GetString("reporter.elasticsearch.url"),
		&http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
		logger,
	)
	api := api.NewScanAPI(scanner, store, logger, &api.Opt{
		Insecure: true,
		Debug:    true,
		SkipPing: false,
		Timeout:  time.Minute * 3,
	})

	r := mux.NewRouter()
	r.HandleFunc("/health", health)
	r.HandleFunc("/registry/catalog", api.Catalog).Methods("GET")
	r.HandleFunc("/digest", api.Digest).Methods("GET")
	r.HandleFunc("/manifest", api.Manifest).Methods("GET")
	r.HandleFunc("/scan", api.Scan).Methods("POST")
	// r.HandleFunc("/image/layer", api.Layer)

	s := &http.Server{
		Addr:           ":8080",
		Handler:        r,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}

	logger.Info("Listening on :8080")
	logger.Fatal(s.ListenAndServe())
}

func health(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}
