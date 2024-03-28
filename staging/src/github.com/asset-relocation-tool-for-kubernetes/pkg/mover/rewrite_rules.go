// Copyright 2021 VMware, Inc.
// SPDX-License-Identifier: BSD-2-Clause

package mover

import (
	"errors"
	"fmt"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
)

// RewriteRules indicate What kind of target registry overrides we want to apply to the found images
type RewriteRules struct {
	// Registry overrides the registry part of the image FQDN, i.e myregistry.io
	Registry string
	// PrefixRegistry add prefix of the registry
	PrefixRegistry string
	// RepositoryPrefix will override the image path by being prepended before the image name
	Repository string
	// PrefixRegistry add prefix of the registry
	PrefixRepository string
	// AppendOriginRegistry when setting up a PrefixRegistry, ture means that the original registry is appended to the
	// new registry, and fasle means that it is moved to the Repositoy field.
	AppendOriginRegistry bool
	// Push the image even if there is already an image with a different digest
	ForcePush bool
}

func (r *RewriteRules) Validate() error {
	var (
		registry   string
		repository string
	)

	if r.PrefixRegistry == "" && r.AppendOriginRegistry {
		return errors.New("AppendOriginRegistry can only be set to ture if PrefixRegistry is set.")
	}

	switch {
	case r.Registry != "" && r.PrefixRegistry != "":
		registry = fmt.Sprintf("%s/%s", r.PrefixRepository, r.Repository)
	case r.Registry != "":
		registry = r.Registry
	case r.PrefixRegistry != "":
		registry = r.PrefixRegistry
	}

	if registry != "" {
		if strings.Contains(registry, "/") {
			_, err := name.NewRepository(registry, name.StrictValidation)
			if err != nil {
				return fmt.Errorf("registry rule is not valid: %w", err)
			}
		} else {
			_, err := name.NewRegistry(registry, name.StrictValidation)
			if err != nil {
				return fmt.Errorf("registry rule is not valid: %w", err)
			}
		}
	}

	switch {
	case r.Repository != "" && r.PrefixRepository != "":
		repository = fmt.Sprintf("%s/%s", r.PrefixRepository, r.Repository)
	case r.Repository != "":
		repository = r.Repository
	case r.PrefixRepository != "":
		repository = r.PrefixRepository
	}

	if repository != "" {
		_, err := name.NewRepository(repository)
		if err != nil {
			return fmt.Errorf("repository rule is not valid: %w", err)
		}
	}
	return nil
}
