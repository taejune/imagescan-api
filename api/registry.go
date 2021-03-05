package api

import (
	"encoding/json"
	"net/http"
)

func Catalog(w http.ResponseWriter, r *http.Request) {

	c, err := NewRegistryFrom(r)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(err.Error()))
	}

	catalog, err := c.Catalog(r.Context(), "")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(err.Error()))
		return
	}

	dat, _ := json.Marshal(catalog)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(dat)
}
