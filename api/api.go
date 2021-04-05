package api

import (
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strings"
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
			h.logger.Error("authentication parameters missing")
			http.Error(w, "authentication parameters missing", http.StatusUnauthorized)
			return
		}

		registryURL := ""
		imgParam, _ := url.QueryUnescape(r.FormValue("image"))
		if len(imgParam) > 0 {
			img, err := registry.ParseImage(imgParam)
			if err != nil {
				h.logger.Error(err)
				http.Error(w, "image parsing failed", http.StatusInternalServerError)
				return
			}
			registryURL = img.Domain
		} else {
			regParam, _ := url.QueryUnescape(r.FormValue("reg"))
			if regParam == "" {
				http.Error(w, "cannot parse registry url", http.StatusBadRequest)
				return
			}
			registryURL = regParam
		}

		// Prevent repoutils.GetAuthConfig() from loading local .docker/config.json
		if registryURL == "docker.io" {
			registryURL = "registry-1.docker.io"
		}

		config, err := repoutils.GetAuthConfig(username, password, registryURL)
		if err != nil {
			h.logger.Error(err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
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
		ctx := WithRegistry(r.Context(), reg)

		images := []*registry.Image{}
		catalog, err := reg.Catalog(r.Context(), "")
		h.logger.Info("catalog", catalog)

		imgsParam, err := url.QueryUnescape(r.FormValue("images"))
		if err != nil {
			h.logger.Error(err)
			http.Error(w, "image parsing failed", http.StatusInternalServerError)
			return
		} else if len(imgsParam) > 0 {
			resolvedImgs := resolvImage(catalog, strings.Split(imgsParam, ","))
			for _, resolvedImg := range resolvedImgs {
				img, err := registry.ParseImage(path.Join(registryURL, resolvedImg))
				if err != nil {
					h.logger.Error(err)
					http.Error(w, "image parsing failed", http.StatusInternalServerError)
					return
				}
				images = append(images, &img)
			}
		} else {
			imgParam, err := url.QueryUnescape(r.FormValue("image"))
			if err != nil {
				h.logger.Error(err)
				http.Error(w, "image parsing failed", http.StatusInternalServerError)
				return
			}
			resolvedImgs := resolvImage(catalog, []string{imgParam})
			for _, resolvedImg := range resolvedImgs {
				img, err := registry.ParseImage(path.Join(registryURL, resolvedImg))
				if err != nil {
					h.logger.Error(err)
					http.Error(w, "image parsing failed", http.StatusInternalServerError)
					return
				}
				images = append(images, &img)
			}
		}

		ctx = WithImages(ctx, images)
		next(w, r.WithContext(ctx))
	})
}

func resolvImage(catalog []string, targets []string) []string {
	resolved := []string{}
	for _, t := range targets {
		if strings.ContainsAny("*?", t) {
			for _, r := range catalog {
				if isMatch, _ := regexp.MatchString(convertToRegexp(t), r); isMatch {
					resolved = append(resolved, r)
					break
				}
			}
		} else {
			resolved = append(resolved, t)
		}
	}
	return resolved
}

func convertToRegexp(s string) string {
	c1 := strings.ReplaceAll(s, "?", ".")
	c2 := strings.ReplaceAll(c1, "*", "[[:alnum:]]")

	return c2
}
