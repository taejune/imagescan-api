package api

import (
	"fmt"
	"log"
	"net/http"
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
	opt     Opt
}

type Opt struct {
	Insecure bool
	Debug    bool
	SkipPing bool
	Timeout  time.Duration
}

func NewScanAPI(scanner *clair.Clair, store *store.Store, logger *zap.SugaredLogger, opt Opt) *ScanAPI {
	return &ScanAPI{
		scanner: scanner,
		store:   store,
		logger:  logger,
		opt:     opt,
	}
}

func NewRegistryFrom(r *http.Request, opt Opt) (*registry.Registry, error) {
	username, password, ok := r.BasicAuth()
	if !ok {
		return nil, fmt.Errorf("Authentication parameters missing")
	}

	reg := r.FormValue("url")
	if reg == "" {
		return nil, fmt.Errorf("Registry address missing")
	}

	config, _ := repoutils.GetAuthConfig(username, password, reg)
	c, err := registry.New(r.Context(), config, registry.Opt{
		Insecure: opt.Insecure,
		Debug:    opt.Debug,
		SkipPing: opt.SkipPing,
		Timeout:  opt.Timeout,
	})
	if err != nil {
		return nil, err
	}

	return c, nil
}

func NewImagesFrom(r *http.Request) (map[string]*registry.Image, error) {

	ret := map[string]*registry.Image{}

	images := r.FormValue("names")
	if images == "" {
		return nil, fmt.Errorf("Target images missing")
	}
	log.Printf("/image/digest: Target images: %s\n", images)

	for _, e := range strings.Split(images, ",") {
		img, err := registry.ParseImage(e)
		if err != nil {
			return nil, fmt.Errorf("Parsing image(%s) failed: %s", e, err)
		}

		ret[e] = &img
		log.Printf("Domain: %s | Path: %s | Tag: %s | Digest: %s | Reference: %s\n", img.Domain, img.Path, img.Tag, img.Digest, img.Reference())
	}

	return ret, nil
}
