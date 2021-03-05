package api

import (
	"context"
	"net/http"
	"strings"
)

func Catalog(w http.ResponseWriter, r *http.Request) {

	c, err := NewRegistryFrom(r)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(err.Error()))
	}

	catalog, err := c.Catalog(context.Background(), "")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(err.Error()))
		return
	}

	w.WriteHeader(http.StatusOK)
	// FIXME: convert to json
	w.Write([]byte(strings.Join(catalog, ", ")))
}
