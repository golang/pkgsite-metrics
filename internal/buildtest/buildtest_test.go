// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package buildtest

import (
	"testing"
)

func TestBuildGovulncheck(t *testing.T) {
	if _, err := BuildGovulncheck(t.TempDir()); err != nil {
		t.Fatal(err)
	}
}
