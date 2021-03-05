package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/genuinetools/reg/registry"
	"github.com/genuinetools/reg/repoutils"
)

func Digest(w http.ResponseWriter, r *http.Request) {

	username, password, ok := r.BasicAuth()
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("Authentication parameter missing"))
		return
	}

	imgs, err := NewImagesFrom(r)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(err.Error()))
	}

	imgDigest := map[string]string{}
	for name, img := range imgs {
		config, _ := repoutils.GetAuthConfig(username, password, img.Domain)
		c, err := registry.New(context.TODO(), config, registry.Opt{
			Insecure: true,
			Debug:    true,
			SkipPing: false,
			Timeout:  time.Second * 3,
		})
		if err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			w.Write([]byte(err.Error()))
			return
		}

		d, err := c.Digest(r.Context(), *img)
		if err != nil {
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(fmt.Sprintf("%s - %s\n", err, name)))
			return
		}

		log.Printf("Digest: %s \n", d)
		imgDigest[name] = string(d)
	}

	dat, err := json.Marshal(imgDigest)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(err.Error()))
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(dat)
}

// func Scan(w http.ResponseWriter, r *http.Request) {

// 	username, password, ok := r.BasicAuth()
// 	if !ok {
// 		w.WriteHeader(http.StatusUnauthorized)
// 		w.Write([]byte("Authentication parameter missing"))
// 		return
// 	}

// 	imgs, err := NewImagesFrom(r)
// 	if err != nil {
// 		w.WriteHeader(http.StatusBadRequest)
// 		w.Write([]byte(err.Error()))
// 	}

// 	ctx := r.Context()
// 	summary := map[string]int{}
// 	for _, img := range imgs {
// 		config, _ := repoutils.GetAuthConfig(username, password, img.Domain)
// 		c, err := registry.New(context.TODO(), config, registry.Opt{
// 			Insecure: true,
// 			Debug:    true,
// 			SkipPing: false,
// 			Timeout:  time.Second * 3,
// 		})
// 		if err != nil {
// 			w.WriteHeader(http.StatusServiceUnavailable)
// 			w.Write([]byte(err.Error()))
// 			return
// 		}

// 		report, err := scanner.Vulnerabilities(ctx, c, img.Path, img.Reference())
// 		if err != nil {
// 			w.WriteHeader(http.StatusBadRequest)
// 			w.Write([]byte(err.Error()))
// 			return
// 		}

// 		for severity, vulnerabilityList := range report.VulnsBySeverity {
// 			summary[severity] = len(vulnerabilityList)
// 		}
// 	}

// 	dat, err := json.Marshal(summary)
// 	if err != nil {
// 		w.WriteHeader(http.StatusBadRequest)
// 		w.Write([]byte(err.Error()))
// 		return
// 	}

// 	w.WriteHeader(http.StatusOK)
// 	w.Write(dat)
// }
