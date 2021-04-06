package api

import (
	"net/http"
	"net/url"
	"time"

	"github.com/genuinetools/reg/clair"
	"github.com/genuinetools/reg/registry"
	"github.com/genuinetools/reg/repoutils"
	"github.com/taejune/imagescan-api/store"
	"go.uber.org/zap"
)

type ScanAPI struct {
	// FIXME: how to deal with other scanner type? (e.q: trivy)
	scanner *clair.Clair
	store   *store.Store
	logger  *zap.SugaredLogger
	opt     *Opt
}

type Opt struct {
	Insecure bool
	Debug    bool
	SkipPing bool
	Timeout  time.Duration
}

func NewScanAPI(scanner *clair.Clair, store *store.Store, logger *zap.SugaredLogger, opt *Opt) *ScanAPI {
	return &ScanAPI{
		scanner: scanner,
		store:   store,
		logger:  logger.Named("api"),
		opt:     opt,
	}
}

func (h *ScanAPI) Middleware(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		if !ok {
			http.Error(w, "authentication parameters missing", http.StatusUnauthorized)
			return
		}

		insecureOpt := h.opt.Insecure
		insecureParam := r.FormValue("insecure")
		if insecureParam != "" {
			insecureOpt = true
		}

		imgParam, _ := url.QueryUnescape(r.FormValue("image"))
		img, err := registry.ParseImage(imgParam)
		if err != nil {
			h.logger.Error(err)
			http.Error(w, "image parsing failed", http.StatusInternalServerError)
			return
		}

		// Prevent repoutils.GetAuthConfig() from loading local .docker/config.json
		registryURL := img.Domain
		if img.Domain == "docker.io" {
			registryURL = "registry-1.docker.io"
		}

		config, err := repoutils.GetAuthConfig(username, password, registryURL)
		if err != nil {
			h.logger.Error(err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		reg, err := registry.New(r.Context(), config, registry.Opt{
			Insecure: insecureOpt,
			Debug:    h.opt.Debug,
			SkipPing: h.opt.SkipPing,
			Timeout:  h.opt.Timeout,
		})
		if err != nil {
			h.logger.Error(err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		ctx := WithImage(r.Context(), &img)
		ctx = WithRegistry(ctx, reg)
		next(w, r.WithContext(ctx))
	})
}
