package api

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/docker/distribution"
	"github.com/genuinetools/reg/clair"
	"github.com/genuinetools/reg/registry"
	"github.com/genuinetools/reg/repoutils"
	"github.com/spf13/viper"
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
		c, err := registry.New(r.Context(), config, registry.Opt{
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

func Manifest(w http.ResponseWriter, r *http.Request) {

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

	imgDigest := map[string]distribution.Manifest{}
	for name, img := range imgs {
		config, _ := repoutils.GetAuthConfig(username, password, img.Domain)
		c, err := registry.New(r.Context(), config, registry.Opt{
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

		m, err := c.Manifest(r.Context(), img.Path, img.Reference())
		if err != nil {
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(fmt.Sprintf("%s - %s\n", err, name)))
			return
		}

		log.Printf("Manifest: %s \n", m)
		imgDigest[name] = m
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

func Layer(w http.ResponseWriter, r *http.Request) {

	// username, password, ok := r.BasicAuth()
	// if !ok {
	// 	w.WriteHeader(http.StatusUnauthorized)
	// 	w.Write([]byte("Authentication parameter missing"))
	// 	return
	// }

	imgs, err := NewImagesFrom(r)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(err.Error()))
	}

	ctx := r.Context()
	// FIXME: how to deal with other scanner type? (e.q: trivy)
	scanner, _ := clair.New(viper.GetString("scanner.clair.url"), clair.Opt{
		Debug:    true,
		Insecure: false,
		Timeout:  time.Second * 3,
	})

	layers := map[string]*clair.Layer{}
	for name, img := range imgs {
		// config, _ := repoutils.GetAuthConfig(username, password, img.Domain)
		// c, err := registry.New(r.Context(), config, registry.Opt{
		// 	Insecure: true,
		// 	Debug:    true,
		// 	SkipPing: false,
		// 	Timeout:  time.Second * 3,
		// })
		// if err != nil {
		// 	w.WriteHeader(http.StatusServiceUnavailable)
		// 	w.Write([]byte(err.Error()))
		// 	return
		// }

		clairLayer, err := scanner.GetLayer(ctx, img.Path, true, true)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(err.Error()))
			return
		}

		layers[name] = clairLayer
	}

	dat, err := json.Marshal(layers)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(err.Error()))
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(dat)
}

func Scan(w http.ResponseWriter, r *http.Request) {

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

	ctx := r.Context()
	// FIXME: how to deal with other scanner type? (e.q: trivy)
	scanner, _ := clair.New(viper.GetString("scanner.clair.url"), clair.Opt{
		Debug:    true,
		Insecure: false,
		Timeout:  time.Second * 3,
	})

	// reporter := report.NewReporter(viper.GetString("reporter.elasticsearch.url"),
	// 	&http.Transport{
	// 		TLSClientConfig: &tls.Config{
	// 			InsecureSkipVerify: true,
	// 		},
	// 	},
	// )

	summary := map[string]int{}
	for _, img := range imgs {
		config, _ := repoutils.GetAuthConfig(username, password, img.Domain)
		c, err := registry.New(ctx, config, registry.Opt{
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

		clairReport, err := scanner.Vulnerabilities(ctx, c, img.Path, img.Tag)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(err.Error()))
			return
		}

		for severity, vulnerabilityList := range clairReport.VulnsBySeverity {
			summary[severity] = len(vulnerabilityList)
		}

		// go reporter.SendReport(path.Join(img.Path, img.Tag), clairReport.Vulns)
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
