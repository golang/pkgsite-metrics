// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package worker

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"testing"

	"cloud.google.com/go/storage"
	"golang.org/x/pkgsite-metrics/internal/bigquery"
	"golang.org/x/pkgsite-metrics/internal/config"
	"golang.org/x/pkgsite-metrics/internal/govulncheck"
	"golang.org/x/pkgsite-metrics/internal/proxy"
	vulnclient "golang.org/x/vuln/client"
)

var integration = flag.Bool("integration", false, "test against actual service")

func TestAsScanError(t *testing.T) {
	check := func(err error, want bool) {
		if got := errors.As(err, new(scanError)); got != want {
			t.Errorf("%T: got %t, want %t", err, got, want)
		}
	}
	check(io.EOF, false)
	check(scanError{io.EOF}, true)
}

func TestVulnsForMode(t *testing.T) {
	vulns := []*govulncheck.Vuln{
		&govulncheck.Vuln{Symbol: "A", CallSink: bigquery.NullInt(0)},
		&govulncheck.Vuln{Symbol: "B"},
		&govulncheck.Vuln{Symbol: "C", CallSink: bigquery.NullInt(9)},
	}

	vulnsStr := func(vulns []*govulncheck.Vuln) string {
		var vs []string
		for _, v := range vulns {
			vs = append(vs, fmt.Sprintf("%s:%d", v.Symbol, v.CallSink.Int64))
		}
		return strings.Join(vs, ", ")
	}

	for _, tc := range []struct {
		mode string
		want string
	}{
		{modeImports, "A:0, B:0, C:0"},
		{ModeGovulncheck, "C:9"},
		{ModeBinary, "A:0, B:0, C:9"},
	} {
		tc := tc
		t.Run(tc.mode, func(t *testing.T) {
			modeVulns := vulnsForMode(vulns, tc.mode)
			if got := vulnsStr(modeVulns); got != tc.want {
				t.Errorf("got %s; want %s", got, tc.want)
			}
		})
	}
}

func TestRunScanModule(t *testing.T) {
	t.Skip("breaks on trybots")

	ctx := context.Background()
	cfg, err := config.Init(ctx)
	if err != nil {
		t.Fatal(err)
	}
	dbClient, err := vulnclient.NewClient([]string{cfg.VulnDBURL}, vulnclient.Options{})
	if err != nil {
		t.Fatal(err)
	}
	proxyClient, err := proxy.New(cfg.ProxyURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Run("binary", func(t *testing.T) {
		if !*integration { // needs GCS read permission, not available on kokoro
			t.Skip("missing -integration")
		}
		s := &scanner{proxyClient: proxyClient, dbClient: dbClient}
		gcsClient, err := storage.NewClient(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		s.gcsBucket = gcsClient.Bucket("go-ecosystem")
		stats := &scanStats{}
		vulns, err := s.runScanModule(ctx, "golang.org/x/pkgsite", "v0.0.0-20221004150836-873fb37c2479", "cmd/worker", ModeBinary, stats)
		if err != nil {
			t.Fatal(err)
		}
		if g, w := len(vulns), 14; g != w {
			t.Errorf("got %d vulns, want %d", g, w)
		}
	})
	t.Run("govulncheck", func(t *testing.T) {
		s := &scanner{proxyClient: proxyClient, dbClient: dbClient, insecure: true}
		stats := &scanStats{}
		vulns, err := s.runScanModule(ctx,
			"golang.org/x/exp/event", "v0.0.0-20220929112958-4a82f8963a65",
			"", ModeGovulncheck, stats)
		if err != nil {
			t.Fatal(err)
		}
		wantID := "GO-2022-0493"
		found := false
		for _, v := range vulns {
			if v.ID == wantID {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("want %s, did not find it in %d vulns", wantID, len(vulns))
		}
		if got := stats.scanSeconds; got <= 0 {
			t.Errorf("scan time not collected or negative: %v", got)
		}
		if got := stats.scanMemory; got <= 0 {
			t.Errorf("scan memory not collected or negative: %v", got)
		}
	})
}
