package api

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/genuinetools/reg/registry"
	"github.com/genuinetools/reg/repoutils"
)

func NewRegistryFrom(r *http.Request) (*registry.Registry, error) {
	username, password, ok := r.BasicAuth()
	if !ok {
		return nil, fmt.Errorf("Authentication parameters missing")
	}

	reg := r.FormValue("url")
	if reg == "" {
		return nil, fmt.Errorf("Registry address missing")
	}

	config, _ := repoutils.GetAuthConfig(username, password, reg)
	c, err := registry.New(context.TODO(), config, registry.Opt{
		Insecure: true,
		Debug:    true,
		SkipPing: false,
		Timeout:  time.Second * 3,
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
