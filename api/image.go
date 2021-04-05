package api

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/docker/distribution"
	"github.com/opencontainers/go-digest"
	"net/http"
)

type DigestResponse struct {
	Digest map[string]digest.Digest `json:"digest"`
}

func (h *ScanAPI) Digest(w http.ResponseWriter, r *http.Request) {
	imgs := ImagesFrom(r.Context())
	c := RegistryFrom(r.Context())

	h.logger.Infow("digest", "url", c.URL, "user", c.Username, "password", "...",
		"images", imgs)
	response := DigestResponse{}
	for _, img := range imgs {
		d, err := c.Digest(r.Context(), *img)
		if err != nil {
			http.Error(w, fmt.Sprintf("failed to get digest(%s): %s\n", img.Path, err), http.StatusNotFound)
			return
		}
		response.Digest[img.Path+":"+img.Tag] = d
	}

	dat, err := json.Marshal(response)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(dat)
}

type ManifestResponse struct {
	Manifest map[string]distribution.Manifest `json:"manifest"`
}

func (h *ScanAPI) Manifest(w http.ResponseWriter, r *http.Request) {
	imgs := ImagesFrom(r.Context())
	c := RegistryFrom(r.Context())

	h.logger.Infow("manifest", "url", c.URL, "user", c.Username, "password", "...",
		"images", imgs)

	response := ManifestResponse{}
	for _, img := range imgs {
		manifest, err := c.Manifest(r.Context(), img.Path, img.Reference())
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to fetch manifest(%s): %s\n", img.Path, err), http.StatusNotFound)
			return
		}
		response.Manifest[img.Path+":"+img.Tag] = manifest
	}

	dat, err := json.Marshal(response)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(dat)
}

type ScanResponse struct {
	Scan map[string]string `json:"scan"`
}

func (h *ScanAPI) Scan(w http.ResponseWriter, r *http.Request) {
	imgs := ImagesFrom(r.Context())
	c := RegistryFrom(r.Context())

	h.logger.Infow("scan", "url", c.URL, "user", c.Username, "password", "...",
		"images", imgs)

	response := ScanResponse{}
	for _, img := range imgs {
		d, err := c.Digest(r.Context(), *img)
		if err != nil {
			response.Scan[img.Path+":"+img.Tag] = "failed to fetch digest"
			continue
		}

		h.logger.Infow("check if been scanned before",
			"digest", d, "image", img.Path, "tag", img.Tag)
		if IsScanning(d) {
			response.Scan[img.Path+":"+img.Tag] = "already in scanning"
			continue
		}
		isScanned, err := h.store.Exist(string(d))
		if err != nil {
			response.Scan[img.Path+":"+img.Tag] = "failed to check if in storage"
			continue
		}
		if isScanned {
			response.Scan[img.Path+":"+img.Tag] = "has been scanned before"
			continue
		}

		img := img
		go func() {
			h.logger.Infow("start scanning...",
				"digest", d, "image", img.Path, "tag", img.Tag)

			AddScanning(d)
			defer RemoveScanning(d)

			report, err := h.scanner.Vulnerabilities(context.Background(), c, img.Path, img.Tag)
			if err != nil {
				h.logger.Error(err)
				return
			}
			h.logger.Infow("scanning done. save report...", "digest", d,
				"image", img.Path, "tag", img.Tag, "name", report.Name, "tag", report.Tag)

			dat, err := json.Marshal(report)
			err = h.store.Save(string(d), dat)
			if err != nil {
				h.logger.Error(err)
			}
			h.logger.Infow("save done", "digest", d,
				"image", img.Path, "tag", img.Tag, "name", report.Name, "tag", report.Tag)
		}()
	}

	dat, err := json.Marshal(response)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(dat)
}

type ReportResponse struct {
	Report map[string]string `json:"report"`
}

func (h *ScanAPI) Report(w http.ResponseWriter, r *http.Request) {
	imgs := ImagesFrom(r.Context())
	c := RegistryFrom(r.Context())

	h.logger.Infow("report", "url", c.URL, "user", c.Username, "password", "...",
		"images", imgs)

	response := ReportResponse{}
	for _, img := range imgs {
		d, err := c.Digest(r.Context(), *img)
		if err != nil {
			response.Report[img.Path+":"+img.Tag] = "failed to fetch digest"
			continue
		}

		if IsScanning(d) {
			response.Report[img.Path+":"+img.Tag] = "scanning not finished"
			continue
		}

		h.logger.Infow("fetch from store", "digest", d)
		doc, err := h.store.Get(string(d))
		if err != nil {
			response.Report[img.Path+":"+img.Tag] = "failed to fetch report"
			continue
		}
		report, err := json.Marshal(doc)
		response.Report[img.Path+":"+img.Tag] = string(report)
	}

	dat, err := json.Marshal(response)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(dat)
}
