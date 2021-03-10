package api

import (
	"encoding/json"
	"fmt"
	"net/http"
)

func (h *ScanAPI) Digest(w http.ResponseWriter, r *http.Request) {

	img := ImageFrom(r.Context())
	c := RegistryFrom(r.Context())

	digest, err := c.Digest(r.Context(), *img)
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

	img := ImageFrom(r.Context())
	c := RegistryFrom(r.Context())

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

	img := ImageFrom(r.Context())
	c := RegistryFrom(r.Context())

	digest, err := c.Digest(r.Context(), *img)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to fetch digest(%s): %s\n", img.Path, err), http.StatusNotFound)
		return
	}

	report, err := h.scanner.Vulnerabilities(r.Context(), c, img.Path, img.Tag)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	go h.store.Save(string(digest), report)

	dat, err := json.Marshal(report)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(dat)
}

func (h *ScanAPI) Report(w http.ResponseWriter, r *http.Request) {

	img := ImageFrom(r.Context())
	c := RegistryFrom(r.Context())

	digest, err := c.Digest(r.Context(), *img)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to fetch digest(%s): %s\n", img.Path, err), http.StatusNotFound)
		return
	}

	h.logger.Infow("Fetch report from store", "digest", digest)
	report, err := h.store.Get(string(digest))
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to fetch report(%s): %s\n", digest, err), http.StatusNotFound)
		return
	}

	dat, err := json.Marshal(report)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(dat)
}
