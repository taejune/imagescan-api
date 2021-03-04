package main

import (
	"context"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/genuinetools/reg/clair"
	"github.com/genuinetools/reg/registry"
	"github.com/genuinetools/reg/repoutils"
	"github.com/gorilla/mux"

	"github.com/taejune/imagescan-api/internal"
)

var (
	scanner *clair.Clair
)

func main() {

	clairURL := "http://172.22.11.2:30060"
	scanner, _ = clair.New(clairURL, clair.Opt{
		Debug:    true,
		Insecure: false,
		Timeout:  time.Second * 3,
	})

	r := mux.NewRouter()
	r.HandleFunc("/health", HealthHandler)
	r.HandleFunc("/registry/health", RegistryHealthHandler)
	r.HandleFunc("/registry/catalog", RegistryCatalogHandler)
	r.HandleFunc("/image/scan", ScanHandler)

	s := &http.Server{
		Addr:           ":8080",
		Handler:        r,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}

	log.Println("Listening on :8080")
	log.Fatal(s.ListenAndServe())
}

func HealthHandler(w http.ResponseWriter, r *http.Request) {

	log.Println("/health: Got request")

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func RegistryHealthHandler(w http.ResponseWriter, r *http.Request) {

	log.Println("/registry/health: Got request")

	// Parse the Authorization header
	username, password, err := internal.ParseBasicAuthHeader(r)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(err.Error()))
		return
	}

	log.Printf("/registry/health: User credential: %s:%s\n", username, password)

	// Parse the query params
	regAddrs, isRegAddrPresent := r.URL.Query()["url"]
	if !isRegAddrPresent {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("No registry address presented."))
		return
	}

	for _, u := range regAddrs {
		log.Printf("/registry/health: Registry url: %s \n", u)
	}

	_, err = NewClient(regAddrs[0], username, password, registry.Opt{
		Insecure: true,
		Debug:    true,
		SkipPing: false,
		Timeout:  time.Second * 3,
	})
	if err != nil {
		w.WriteHeader(http.StatusFailedDependency)
		w.Write([]byte(err.Error()))
		return
	}

	w.Write([]byte("OK"))
	w.WriteHeader(http.StatusOK)
}

func RegistryCatalogHandler(w http.ResponseWriter, r *http.Request) {

	log.Println("/registry/health: Got request")

	// Parse the Authorization header
	username, password, err := internal.ParseBasicAuthHeader(r)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(err.Error()))
		return
	}

	log.Printf("/registry/health: User credential: %s:%s\n", username, password)

	// Parse the query params
	regAddrs, isRegAddrPresent := r.URL.Query()["url"]
	if !isRegAddrPresent {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("No registry address presented."))
		return
	}

	for _, u := range regAddrs {
		log.Printf("/registry/health: Registry url: %s \n", u)
	}

	c, err := NewClient(regAddrs[0], username, password, registry.Opt{
		Insecure: true,
		Debug:    true,
		SkipPing: false,
		Timeout:  time.Second * 3,
	})
	if err != nil {
		w.WriteHeader(http.StatusFailedDependency)
		w.Write([]byte(err.Error()))
		return
	}

	catalog, err := c.Catalog(context.Background(), "")
	if err != nil {
		w.WriteHeader(http.StatusFailedDependency)
		w.Write([]byte(err.Error()))
		return
	}

	w.WriteHeader(http.StatusOK)
	// FIXME: convert to json
	w.Write([]byte(strings.Join(catalog, ", ")))
}

func ScanHandler(w http.ResponseWriter, r *http.Request) {

	log.Println("/image/scan: Got request")

	// TODO:
	w.WriteHeader(http.StatusOK)
}

func NewClient(url, username, password string, opt registry.Opt) (*registry.Registry, error) {

	config, err := repoutils.GetAuthConfig(username, password, url)
	if err != nil {
		return nil, err
	}

	// TODO: Set opt from operator's registry config.
	r, err := registry.New(context.TODO(), config, opt)
	if err != nil {
		return nil, err
	}

	return r, nil
}
