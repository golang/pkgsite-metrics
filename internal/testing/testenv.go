// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package testing provides testing utilities.
package testing

import (
	"os"
	"os/exec"
	"testing"
)

// NeedsGoEnv skips t if the current system can't get the environment with
// “go env” in a subprocess.
func NeedsGoEnv(t testing.TB) {
	t.Helper()

	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("skipping test: can't run go env")
	}
}

// NeedsIntegrationEnv skips t if the underlying test satisfies integration
// requirements. It must be executed in the non-short test mode with an
// appropriate integration environment.
func NeedsIntegrationEnv(t testing.TB) {
	t.Helper()

	if os.Getenv("GO_ECOSYSTEM_INTEGRATION_TESTING") != "1" {
		t.Skip("skipping; need local test environment with GCS permissions (set GO_ECOSYSTEM_INTEGRATION_TESTING=1)")
	}
	if testing.Short() {
		t.Skip("skipping; integration tests must be run in non-short mode")
	}
}
