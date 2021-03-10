package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/genuinetools/reg/registry"
	"github.com/genuinetools/reg/repoutils"
)

func (h *ScanAPI) Digest(w http.ResponseWriter, r *http.Request) {

	imgParam, _ := url.QueryUnescape(r.FormValue("image"))

	img, err := registry.ParseImage(imgParam)
	if err != nil {
		http.Error(w, fmt.Sprintf("Parsing image(%s) failed: %s", imgParam, err), http.StatusInternalServerError)
		return
	}

	username, password, ok := r.BasicAuth()
	if !ok {
		http.Error(w, "Authentication parameters missing", http.StatusUnauthorized)
		return
	}

	config, _ := repoutils.GetAuthConfig(username, password, img.Domain)
	c, err := registry.New(r.Context(), config, registry.Opt{
		Insecure: h.opt.Insecure,
		Debug:    h.opt.Debug,
		SkipPing: h.opt.SkipPing,
		Timeout:  h.opt.Timeout,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	digest, err := c.Digest(r.Context(), img)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to get digest(%s): %s\n", img.Path, err), http.StatusNotFound)
		return
	}

	dat, err := json.Marshal(digest)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(dat)
}

func (h *ScanAPI) Manifest(w http.ResponseWriter, r *http.Request) {

	imgParam, _ := url.QueryUnescape(r.FormValue("image"))

	img, err := registry.ParseImage(imgParam)
	if err != nil {
		http.Error(w, fmt.Sprintf("Parsing image(%s) failed: %s", imgParam, err), http.StatusInternalServerError)
		return
	}

	username, password, ok := r.BasicAuth()
	if !ok {
		http.Error(w, "Authentication parameters missing", http.StatusUnauthorized)
		return
	}

	config, _ := repoutils.GetAuthConfig(username, password, img.Domain)
	c, err := registry.New(r.Context(), config, registry.Opt{
		Insecure: h.opt.Insecure,
		Debug:    h.opt.Debug,
		SkipPing: h.opt.SkipPing,
		Timeout:  h.opt.Timeout,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	manifest, err := c.Manifest(r.Context(), img.Path, img.Reference())
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to fetch manifest(%s): %s\n", img.Path, err), http.StatusNotFound)
		return
	}

	dat, err := json.Marshal(manifest)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(dat)
}

func (h *ScanAPI) Scan(w http.ResponseWriter, r *http.Request) {

	imgParam, _ := url.QueryUnescape(r.FormValue("image"))

	img, err := registry.ParseImage(imgParam)
	if err != nil {
		http.Error(w, fmt.Sprintf("Parsing image(%s) failed: %s", imgParam, err), http.StatusInternalServerError)
		return
	}

	username, password, ok := r.BasicAuth()
	if !ok {
		http.Error(w, "Authentication parameters missing", http.StatusUnauthorized)
		return
	}

	config, _ := repoutils.GetAuthConfig(username, password, img.Domain)
	c, err := registry.New(r.Context(), config, registry.Opt{
		Insecure: h.opt.Insecure,
		Debug:    h.opt.Debug,
		SkipPing: h.opt.SkipPing,
		Timeout:  h.opt.Timeout,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	clairReport, err := h.scanner.Vulnerabilities(r.Context(), c, img.Path, img.Tag)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	dat, err := json.Marshal(clairReport)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(dat)

	go h.store.Save(clairReport)
}
