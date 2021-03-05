package main

import (
	"log"
	"net/http"
	"time"

	"github.com/gorilla/mux"

	"github.com/taejune/imagescan-api/api"
)

func main() {

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

	log.Println("Listening on :8080")
	log.Fatal(s.ListenAndServe())
}

func HealthHandler(w http.ResponseWriter, r *http.Request) {

	log.Println("/health: Got request")

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}
