// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package modules

import (
	"context"
	"os"
	"testing"

	"golang.org/x/pkgsite-metrics/internal/proxy"
)

func TestDownload(t *testing.T) {
	t.Skip()

	tempDir, err := os.MkdirTemp("", "testModuleDownload")
	if err != nil {
		t.Fatal(err)
	}

	defer func() {
		if err := os.RemoveAll(tempDir); err != nil {
			t.Fatal(err)
		}
	}()

	proxyClient, err := proxy.New("https://proxy.golang.org")
	if err != nil {
		t.Fatal(err)
	}

	// Use golang.org/x/net@v0.0.0-20221012135044-0b7e1fb9d458
	module := "golang.org/x/net"
	version := "v0.0.0-20221012135044-0b7e1fb9d458"
	if err := Download(context.Background(), module, version, tempDir, proxyClient, true); err != nil {
		t.Errorf("failed to download %v@%v: %v", module, version, err)
	}
}
