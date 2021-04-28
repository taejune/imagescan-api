package api

import (
	"encoding/json"
	"net/http"
)

func (h *ScanAPI) Catalog(w http.ResponseWriter, r *http.Request) {
	c := RegistryFrom(r.Context())
	catalog, err := c.Catalog(r.Context(), "")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	dat, _ := json.Marshal(catalog)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(dat)
}
