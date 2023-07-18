// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build go1.17 && !windows
// +build go1.17,!windows

package main

import (
	"os"
	"os/exec"
	"testing"
)

func Test(t *testing.T) {
	if os.Getenv("GO_ECOSYSTEM_INTEGRATION_TESTING") != "1" {
		t.Log("warning: running go test ./... will skip checking integration tests")
	}

	if testing.Short() {
		t.Skip("skipping test that uses internet in short mode")
	}
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skipf("skipping: %v", err)
	}

	cmd := exec.Command(bash, "./checks.bash")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
}
