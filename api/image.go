package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"path"
)

func (h *ScanAPI) Digest(w http.ResponseWriter, r *http.Request) {

	img := ImageFrom(r.Context())
	c := RegistryFrom(r.Context())

	h.logger.Infow("Start api/Digest", "API", "Digest", "registry", c.URL, "image", path.Join(img.Path, img.Tag))

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

	h.logger.Infow("Start api/Manifest", "API", "Manifest", "registry", c.URL, "image", path.Join(img.Path, img.Tag))

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

	h.logger.Infow("Start api/Scan", "API", "Scan", "registry", c.URL, "image", path.Join(img.Path, img.Tag))

	digest, err := c.Digest(r.Context(), *img)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to fetch digest(%s): %s\n", img.Path, err), http.StatusNotFound)
		return
	}

	if IsScanning(digest) {
		w.WriteHeader(http.StatusNotAcceptable)
		w.Write([]byte("Already in scanning"))
		return
	}

	h.logger.Infow("Check if report already is in the store", "api", "scan", "digest", digest)
	isScanned, err := h.store.Exist(string(digest))
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to fetch report(%s): %s\n", digest, err), http.StatusNotFound)
		return
	}

	if isScanned {
		w.WriteHeader(http.StatusNotAcceptable)
		w.Write([]byte("Already scanned image"))
		return
	}

	go func() {
		AddScanning(digest)
		defer RemoveScanning(digest)

		report, err := h.scanner.Vulnerabilities(context.Background(), c, img.Path, img.Tag)
		if err != nil {
			h.logger.Error(err)
			return
		}
		err = h.store.Save(string(digest), report)
		if err != nil {
			h.logger.Error(err)
		}
	}()

	w.WriteHeader(http.StatusAccepted)
	w.Write([]byte(fmt.Sprintf("Scan image: %s", path.Join(img.Path, img.Tag))))
}

func (h *ScanAPI) Report(w http.ResponseWriter, r *http.Request) {

	img := ImageFrom(r.Context())
	c := RegistryFrom(r.Context())

	h.logger.Infow("Start api/Report", "API", "Report", "registry", c.URL, "image", path.Join(img.Path, img.Tag))

	digest, err := c.Digest(r.Context(), *img)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to fetch digest(%s): %s\n", img.Path, err), http.StatusNotFound)
		return
	}

	if IsScanning(digest) {
		w.WriteHeader(http.StatusNotAcceptable)
		w.Write([]byte("Scanning not finished"))
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
