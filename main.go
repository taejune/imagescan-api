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
}

func main() {

	logger := zap.NewExample().Sugar()
	defer logger.Sync()

	// TODO: Support trivy
	scanner, _ := clair.New(viper.GetString("scanner.url"), clair.Opt{
		Debug:    false,
		Insecure: viper.GetBool("scanner.insecure"),
		Timeout:  time.Second * 3,
	})

	// TODO: Support other storage
	store := store.NewStore(viper.GetString("reporter.url"),
		&http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: viper.GetBool("reporter.insecure"),
			},
		},
		logger,
	)
	api := api.NewScanAPI(scanner, store, logger, &api.Opt{
		Insecure: viper.GetBool("scanner.insecure"),
		Debug:    false,
		SkipPing: false,
		Timeout:  time.Minute * 3,
	})

	r := mux.NewRouter()
	r.HandleFunc("/health", health)
	r.HandleFunc("/registry/catalog", api.Catalog).Methods("GET")
	r.Handle("/digest", api.Middleware(api.Digest)).Methods("GET")
	r.Handle("/manifest", api.Middleware(api.Manifest)).Methods("GET")
	r.Handle("/scan", api.Middleware(api.Scan)).Methods("POST")
	r.Handle("/report", api.Middleware(api.Report)).Methods("GET")
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
