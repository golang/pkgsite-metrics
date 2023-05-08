// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package proxy

import (
	"bytes"
	"io"
	"net/http"
	"net/url"
	"testing"

	test "golang.org/x/pkgsite-metrics/internal/testing"
)

// This module is currently not stored on the proxy.
const missingModule = "code.haiziwang.com/golang/autil"

func TestServer(t *testing.T) {
	test.NeedsIntegrationEnv(t)
	s := ServeDisablingFetch()
	defer s.Close()
	serverURL, err := url.Parse(s.URL)
	if err != nil {
		t.Fatal(err)
	}

	url := serverURL.JoinPath("github.com/pkg/errors/@v/list")
	resp, err := http.Get(url.String())
	if err != nil {
		t.Fatal(err)
	}
	if g, w := resp.StatusCode, 200; g != w {
		t.Fatalf("status: got %d, want %d", g, w)
	}
	defer resp.Body.Close()
	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	want := "v0.8.1\n"
	if !bytes.Contains(got, []byte(want)) {
		t.Errorf("got body %q, missing %q", got, want)
	}

	url = serverURL.JoinPath(missingModule, "/@v/list")
	resp, err = http.Get(url.String())
	if err != nil {
		t.Fatal(err)
	}
	if g, w := resp.StatusCode, http.StatusNotFound; g != w {
		t.Fatalf("status: got %d, want %d", g, w)
	}
}
