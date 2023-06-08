package container

import (
	"fmt"

	"github.com/bitnami-labs/charts-syncer/api"
	"github.com/bitnami-labs/charts-syncer/pkg/client"
	"github.com/bitnami-labs/charts-syncer/pkg/client/container/harbor"
	"github.com/bitnami-labs/charts-syncer/pkg/client/container/jfrog"
	"github.com/bitnami-labs/charts-syncer/pkg/client/types"
)

// NewClient returns a Client object
func NewClient(kind api.Kind, registry string, container *api.Containers, opts ...types.Option) (client.ContainersWriter, error) {
	copts := &types.ClientOpts{}
	for _, o := range opts {
		o(copts)
	}

	insecure := copts.GetInsecure()

	switch kind {
	case api.Kind_HARBOR:
		return harbor.New(registry, container, insecure)
	case api.Kind_JFROG:
		return jfrog.New(registry, container, insecure)
	}

	return nil, fmt.Errorf("%s not supported", kind.String())
}
