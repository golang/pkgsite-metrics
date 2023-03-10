// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package buildtest

import (
	"os"
	"testing"
)

func TestInstallGovulncheck(t *testing.T) {
	t.Skip("breaks on trybots")
	tempDir, err := os.MkdirTemp("", "testInstallGovulncheck")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := os.RemoveAll(tempDir); err != nil {
			t.Fatal(err)
		}
	}()

	if _, err := InstallGovulncheck(tempDir); err != nil {
		t.Fatal(err)
	}
}
