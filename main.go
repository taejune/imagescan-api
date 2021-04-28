package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/genuinetools/reg/clair"
	"github.com/gorilla/mux"
	"github.com/spf13/viper"
	"go.uber.org/zap"

	"github.com/taejune/imagescan-api/pkg/api"
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
	var port int
	var debug bool
	var insecureRegistry bool
	var scannerURL string
	var insecureScanner bool
	var reporterURL string
	var insecureReporter bool

	flag.IntVar(&port, "port", 8080, "The server port number(default: 8080)")
	flag.BoolVar(&debug, "debug", false, "verbose")
	flag.BoolVar(&insecureRegistry, "registry-insecure", viper.GetBool("registry.insecure"),
		"Allow insecure connection to registry")
	flag.StringVar(&scannerURL, "scanner-url", viper.GetString("scanner.url"), "The URL of scanner")
	flag.BoolVar(&insecureScanner, "scanner-insecure", viper.GetBool("scanner.insecure"),
		"Allow insecure connection to scanner")
	flag.StringVar(&reporterURL, "reporter-url", viper.GetString("reporter.url"), "The URL of reporter")
	flag.BoolVar(&insecureReporter, "reporter-insecure", viper.GetBool("reporter.insecure"),
		"Allow insecure connection to reporter")
	flag.Parse()

	logger := zap.NewExample().Sugar()
	defer logger.Sync()

	// TODO: Support trivy
	scanner, _ := clair.New(scannerURL, clair.Opt{
		Debug:    debug,
		Insecure: insecureScanner,
		Timeout:  time.Minute * 5,
	})

	// TODO: Support other storage
	storage := store.NewStore(reporterURL,
		&http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: insecureReporter,
			},
		},
		logger,
	)
	scanAPI := api.NewScanAPI(scanner, storage, logger, &api.Opt{
		Insecure: insecureRegistry,
		Debug:    debug,
		SkipPing: true,
		Timeout:  time.Minute * 5,
	})

	r := mux.NewRouter()
	r.HandleFunc("/health", health)
	r.PathPrefix("/api/catalog").Handler(scanAPI.Middleware(scanAPI.Catalog)).Methods("GET")
	r.PathPrefix("/api/digest").Handler(scanAPI.Middleware(scanAPI.Digest)).Methods("GET")
	r.PathPrefix("/api/manifest").Handler(scanAPI.Middleware(scanAPI.Manifest)).Methods("GET")
	r.PathPrefix("/api/scan").Handler(scanAPI.Middleware(scanAPI.Scan)).Methods("POST")
	r.PathPrefix("/api/scan").Handler(scanAPI.Middleware(scanAPI.Report)).Methods("GET")
	// r.HandleFunc("/image/layer", scanAPI.Layer)

	s := &http.Server{
		Addr:           ":" + strconv.Itoa(port),
		Handler:        r,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}

	logger.Infow("Listening on " + strconv.Itoa(port))
	logger.Fatal(s.ListenAndServe())
}

func health(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("OK"))
}
