package api

import (
	"encoding/json"
	"net/http"
)

func Catalog(w http.ResponseWriter, r *http.Request) {

	c, err := NewRegistryFrom(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	catalog, err := c.Catalog(r.Context(), "")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	dat, _ := json.Marshal(catalog)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(dat)
}
