// Copyright 2021 VMware, Inc.
// SPDX-License-Identifier: BSD-2-Clause

package provider_test

import (
	"testing"

	. "github.com/onsi/ginkgo"
)

func TestInternal(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Internal Suite")
}
