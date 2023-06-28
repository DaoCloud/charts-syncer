package util

import "github.com/bitnami-labs/charts-syncer/api"

func CheckoutSupportAutoCreateRepository(kind api.Kind) bool {
	switch kind {
	case api.Kind_HARBOR:
		fallthrough
	case api.Kind_JFROG:
		return true
	}

	return false
}
