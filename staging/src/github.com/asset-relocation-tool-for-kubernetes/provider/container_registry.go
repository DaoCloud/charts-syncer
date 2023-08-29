// Copyright 2021 VMware, Inc.
// SPDX-License-Identifier: BSD-2-Clause

package provider

import (
	"crypto/tls"
	"fmt"
	"net/http"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

//go:generate counterfeiter . ContainerRegistryInterface
type ContainerRegistryInterface interface {
	Check(digest string, imageReference name.Reference) (bool, error)
	Pull(imageReference name.Reference) (v1.Image, string, error)
	Push(image v1.Image, dest name.Reference) error
}

type ContainerRegistryClient struct {
	auth     authn.Keychain
	insecure bool
	platform v1.Platform
}

func NewContainerRegistryClient(auth authn.Keychain, opts ...Option) *ContainerRegistryClient {
	crc := &ContainerRegistryClient{auth: auth, platform: v1.Platform{
		Architecture: "amd64",
		OS:           "linux",
	}}

	// Option overrides
	for _, opt := range opts {
		if opt != nil {
			opt(crc)
		}
	}
	return crc
}

// Option adds optional functionality to NewContainerRegistryClient constructor
type Option func(*ContainerRegistryClient)

// WithInsecure sync charts only, without syncing images
func WithInsecure(insecure bool) Option {
	return func(c *ContainerRegistryClient) {
		c.insecure = insecure
	}
}

func WithPlatform(platform v1.Platform) Option {
	return func(c *ContainerRegistryClient) {
		if len(platform.Architecture) > 0 && len(platform.OS) > 0 {
			c.platform = platform
		}
	}
}

func (i *ContainerRegistryClient) Pull(imageReference name.Reference) (v1.Image, string, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if i.insecure {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	image, err := remote.Image(imageReference, remote.WithAuthFromKeychain(i.auth), remote.WithTransport(transport), remote.WithPlatform(i.platform))
	if err != nil {
		return nil, "", fmt.Errorf("failed to pull image %s: %w", imageReference.Name(), err)
	}

	digest, err := image.Digest()
	if err != nil {
		return nil, "", fmt.Errorf("failed to get image digest for %s: %w", imageReference.Name(), err)
	}

	return image, digest.String(), nil
}

func (i *ContainerRegistryClient) Check(digest string, imageReference name.Reference) (bool, error) {
	_, remoteDigest, err := i.Pull(imageReference)

	if err != nil {
		// Return true if failed to pull the image.
		// We see different errors if the image does not exist, or if the specific tag does not exist
		// It is simpler to attempt to push, which will catch legitimate issues (lack of authorization),
		// than it is to try and handle every error case here.
		return true, nil
	}

	if remoteDigest != digest {
		return false, fmt.Errorf("image %s already exists with a different digest "+
			"(local: %s remote: %s). Will not overwrite", imageReference.Name(), digest, remoteDigest)
	}

	return false, nil
}

func (i *ContainerRegistryClient) Push(image v1.Image, dest name.Reference) error {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if i.insecure {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	err := remote.Write(dest, image, remote.WithAuthFromKeychain(i.auth), remote.WithTransport(transport))
	if err != nil {
		return fmt.Errorf("failed to push image %s: %w", dest.Name(), err)
	}

	return nil
}
