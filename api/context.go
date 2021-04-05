package api

import (
	"context"

	"github.com/genuinetools/reg/registry"
)

type (
	imageKey    struct{}
	registryKey struct{}
)

func WithImages(ctx context.Context, imgs []*registry.Image) context.Context {
	return context.WithValue(ctx, imageKey{}, imgs)
}

func ImagesFrom(ctx context.Context) []*registry.Image {
	return ctx.Value(imageKey{}).([]*registry.Image)
}

func WithRegistry(ctx context.Context, reg *registry.Registry) context.Context {
	return context.WithValue(ctx, registryKey{}, reg)
}

func RegistryFrom(ctx context.Context) *registry.Registry {
	return ctx.Value(registryKey{}).(*registry.Registry)
}
