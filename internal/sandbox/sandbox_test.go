// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sandbox

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"

	"golang.org/x/pkgsite-metrics/internal"
)

// These tests require a minimal bundle, in testdata/bundle.
// The Makefile in this directory will build and install
// the binaries needed for the test.

func Test(t *testing.T) {
	t.Skip()

	if os.Getenv("USER") != "root" {
		t.Skip("skipping; must run as root. Run 'make'.")
	}
	ctx := context.Background()
	sb := New("testdata/bundle")
	sb.Runsc = "/usr/local/bin/runsc" // must match path in Makefile

	t.Run("printargs", func(t *testing.T) {
		out, err := sb.Run(ctx, "/printargs", "a", "b")
		if err != nil {
			t.Fatal(internal.IncludeStderr(err))
		}

		want := `args:
0: "a"
1: "b"`
		got := string(out)
		if got != want {
			t.Fatalf("got\n%q\nwant\n%q", got, want)
		}
	})

	t.Run("space in arg", func(t *testing.T) {
		_, err := sb.Run(ctx, "foo", "a b c")
		if err == nil {
			t.Fatal("got nil, want error")
		}
		if g, w := err.Error(), "contains whitespace"; !strings.Contains(g, w) {
			t.Fatalf("got\n%q\nwhich does not contain %q", g, w)
		}
	})

	t.Run("no program", func(t *testing.T) {
		_, err := sb.Run(ctx, "foo")
		var eerr *exec.ExitError
		if !errors.As(err, &eerr) {
			t.Fatalf("got %T, wanted *exec.ExitError", err)
		}
		if g, w := eerr.ExitCode(), 1; g != w {
			t.Fatalf("got exit code %d, wanted %d", g, w)
		}
		if g, w := string(eerr.Stderr), "executable file not found"; !strings.Contains(g, w) {
			t.Fatalf("got\n%q\nwhich does not contain %q", g, w)
		}
	})
}
