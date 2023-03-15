// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package internal

import (
	"testing"

	test "golang.org/x/pkgsite-metrics/internal/testing"
)

func TestGoEnv(t *testing.T) {
	test.NeedsGoEnv(t)

	for _, key := range []string{"GOVERSION", "GOROOT", "GOPATH", "GOMODCACHE"} {
		if m, err := GoEnv(); m[key] == "" {
			t.Errorf("want something for go env %s; got nothing", key)
		} else if err != nil {
			t.Errorf("unexpected error for go env %s: %v", key, err)
		}
	}
}

func TestGoEnvNonVariable(t *testing.T) {
	test.NeedsGoEnv(t)

	key := "NOT_A_GO_ENV_VARIABLE"
	if m, err := GoEnv(); m[key] != "" {
		t.Errorf("expected nothing for go env %s; got %s", key, m[key])
	} else if err != nil {
		t.Errorf("unexpected error for go env %s: %v", key, err)
	}
}
