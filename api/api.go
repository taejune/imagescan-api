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
		logger:  logger,
		opt:     opt,
	}
}

func (h *ScanAPI) Middleware(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		imgParam, _ := url.QueryUnescape(r.FormValue("image"))
		img, err := registry.ParseImage(imgParam)
		if err != nil {
			h.logger.Error(err)
			http.Error(w, "image parsing failed", http.StatusInternalServerError)
			return
		}
		username, password, ok := r.BasicAuth()
		if !ok {
			h.logger.Error(err)
			http.Error(w, "authentication parameters missing", http.StatusUnauthorized)
			return
		}
		config, _ := repoutils.GetAuthConfig(username, password, img.Domain)
		reg, err := registry.New(r.Context(), config, registry.Opt{
			Insecure: h.opt.Insecure,
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
