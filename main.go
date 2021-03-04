package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"path"
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
	r.HandleFunc("/image/scan", ImageScanHandler)

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

func ImageScanHandler(w http.ResponseWriter, r *http.Request) {

	log.Println("/image/scan: Got request")

	// Parse the Authorization header
	username, password, err := internal.ParseBasicAuthHeader(r)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(err.Error()))
		return
	}

	log.Printf("/image/scan: User credential: %s:%s\n", username, password)

	// Parse the query params
	regAddrs, isRegAddrPresent := r.URL.Query()["url"]
	if !isRegAddrPresent {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("No registry address presented."))
		return
	}

	for _, u := range regAddrs {
		log.Printf("/image/scan: Registry url: %s \n", u)
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

	// Parse Image names
	targetImages, isImagesPresent := r.URL.Query()["images"]
	if !isImagesPresent {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Target images not presented."))
		return
	}
	log.Printf("/image/scan: Target images: %s\n", targetImages)

	summary := map[string]int{}
	for _, targetImage := range strings.Split(targetImages[0], ",") {
		img, err := registry.ParseImage(path.Join(c.Domain, targetImage))
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(err.Error()))
			return
		}

		log.Printf("Domain: %s/ Path: %s/ Tag: %s/ Digest: %s/ Reference: %s\n", img.Domain, img.Path, img.Tag, img.Digest, img.Reference())

		report, err := scanner.Vulnerabilities(context.Background(), c, img.Path, img.Reference())
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(err.Error()))
			return
		}

		for severity, vulnerabilityList := range report.VulnsBySeverity {
			summary[severity] = len(vulnerabilityList)
		}
	}

	dat, err := json.Marshal(summary)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(err.Error()))
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(dat)
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
