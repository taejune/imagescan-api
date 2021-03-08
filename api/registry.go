package api

import (
	"encoding/json"
	"net/http"
	"net/url"

	"github.com/genuinetools/reg/registry"
	"github.com/genuinetools/reg/repoutils"
)

func (h *ScanAPI) Catalog(w http.ResponseWriter, r *http.Request) {

	regParam, _ := url.PathUnescape(r.FormValue("url"))

	username, password, ok := r.BasicAuth()
	if !ok {
		http.Error(w, "Authentication parameters missing", http.StatusUnauthorized)
		return
	}

	config, _ := repoutils.GetAuthConfig(username, password, regParam)
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
