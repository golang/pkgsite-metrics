// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package worker

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"

	"golang.org/x/exp/slog"
	"golang.org/x/pkgsite-metrics/internal/derrors"
	"golang.org/x/pkgsite-metrics/internal/log"
	"golang.org/x/pkgsite-metrics/internal/proxy"
	test "golang.org/x/pkgsite-metrics/internal/testing"
)

func TestPrepareModule(t *testing.T) {
	test.NeedsIntegrationEnv(t)
	ctx := context.Background()
	slog.SetDefault(slog.New(log.NewLineHandler(os.Stderr)))
	const insecure = true
	proxyClient, err := proxy.New("https://proxy.golang.org/cached-only")
	if err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		modulePath, version string
		init                bool
		want                error
	}{
		// Bad version; proxy should return an error.
		{"rsc.io/quote", "x", true, derrors.ProxyError},
		// This module has a go.mod file...
		{"rsc.io/quote", "v1.0.0", false, nil},
		// ...so it doesn't matter if we pass true for init.
		{"rsc.io/quote", "v1.0.0", true, nil},
		// This module doesn't have a go.mod file...
		{"github.com/pkg/errors", "v0.9.1", false, derrors.BadModule},
		// ... but passing init will make it work.
		{"github.com/pkg/errors", "v0.9.1", true, nil},
		// This module has a dependency (github.com/decred/blake256) for which
		// the proxy returns 404 when fetch is disabled.
		{"github.com/decred/gominer", "v1.0.0", true, derrors.BadModule},
	} {
		t.Run(fmt.Sprintf("%s@%s,%t", test.modulePath, test.version, test.init), func(t *testing.T) {
			dir := t.TempDir()
			args := prepareModuleArgs{
				modulePath:  test.modulePath,
				version:     test.version,
				dir:         dir,
				proxyClient: proxyClient,
				insecure:    insecure,
				init:        test.init,
			}
			err := prepareModule(ctx, args)
			if !errors.Is(err, test.want) {
				t.Errorf("got %v, want %v", err, test.want)
			}
		})
	}
}
