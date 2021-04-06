package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

func (h *ScanAPI) Digest(w http.ResponseWriter, r *http.Request) {
	img := ImageFrom(r.Context())
	c := RegistryFrom(r.Context())

	h.logger.Infow("digest", "url", c.URL, "user", c.Username, "password", "...",
		"image", img.Path, "tag", img.Tag)

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
	_, _ = w.Write(dat)
}

func (h *ScanAPI) Manifest(w http.ResponseWriter, r *http.Request) {
	img := ImageFrom(r.Context())
	c := RegistryFrom(r.Context())

	h.logger.Infow("manifest", "url", c.URL, "user", c.Username, "password", "...",
		"image", img.Path, "tag", img.Tag)

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
	_, _ = w.Write(dat)
}

func (h *ScanAPI) Scan(w http.ResponseWriter, r *http.Request) {
	img := ImageFrom(r.Context())
	c := RegistryFrom(r.Context())

	h.logger.Infow("scan", "url", c.URL, "user", c.Username, "password", "...",
		"image", img.Path, "tag", img.Tag)

	digest, err := c.Digest(r.Context(), *img)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to fetch digest(%s): %s\n", img.Path, err), http.StatusNotFound)
		return
	}

	h.logger.Infow("check if been scanned before",
		"digest", digest, "image", img.Path, "tag", img.Tag)

	if IsScanning(digest) {
		w.WriteHeader(http.StatusNotAcceptable)
		_, _ = w.Write([]byte("already in scanning"))
		return
	}
	isScanned, err := h.store.Exist(string(digest))
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to fetch report(%s): %s\n", digest, err), http.StatusNotFound)
		return
	}
	if isScanned {
		w.WriteHeader(http.StatusNotAcceptable)
		_, _ = w.Write([]byte("already had been scanned image"))
		return
	}

	go func() {
		h.logger.Infow("start scanning",
			"digest", digest, "image", img.Path, "tag", img.Tag)

		AddScanning(digest)
		defer RemoveScanning(digest)

		report, err := h.scanner.Vulnerabilities(context.Background(), c, img.Path, img.Tag)
		if err != nil {
			h.logger.Error(err)
			return
		}
		h.logger.Infow("scanning done, saving report...", "digest", digest,
			"image", img.Path, "tag", img.Tag, "name", report.Name, "tag", report.Tag)

		dat, _ := json.Marshal(report)
		err = h.store.Save(string(digest), dat)
		if err != nil {
			h.logger.Error(err)
		}
		h.logger.Infow("save done", "digest", digest,
			"image", img.Path, "tag", img.Tag, "name", report.Name, "tag", report.Tag)
	}()
	w.WriteHeader(http.StatusAccepted)
	_, _ = w.Write([]byte("ok"))
}

func (h *ScanAPI) Report(w http.ResponseWriter, r *http.Request) {
	img := ImageFrom(r.Context())
	c := RegistryFrom(r.Context())

	h.logger.Infow("report", "url", c.URL, "user", c.Username, "password", "...",
		"image", img.Path, "tag", img.Tag)

	digest, err := c.Digest(r.Context(), *img)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to fetch digest(%s): %s\n", img.Path, err), http.StatusNotFound)
		return
	}

	if IsScanning(digest) {
		w.WriteHeader(http.StatusNotAcceptable)
		_, _ = w.Write([]byte("Scanning not finished"))
		return
	}

	h.logger.Infow("fetch from store", "digest", digest)
	report, err := h.store.Get(string(digest))
	if err != nil || report == nil {
		http.Error(w, fmt.Sprintf("failed to fetch report", digest), http.StatusNotFound)
		return
	}

	dat, err := json.Marshal(report)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(dat)
}
