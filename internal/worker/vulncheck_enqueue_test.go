// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package worker

import (
	"context"
	"flag"
	"testing"

	"golang.org/x/pkgsite-metrics/internal/scan"
)

var binaryBucket = flag.String("binary-bucket", "", "bucket for scannable binaries")

func TestReadBinaries(t *testing.T) {
	if *binaryBucket == "" {
		t.Skip("missing -binary-bucket")
	}
	sreqs, err := readBinaries(context.Background(), *binaryBucket)
	if err != nil {
		t.Fatal(err)
	}
	want := &scan.Request{
		Module:  "golang.org/x/pkgsite",
		Version: "v0.0.0-20221004150836-873fb37c2479",
		Suffix:  "cmd/worker",
		Mode:    ModeBinary,
	}
	found := false
	for _, sr := range sreqs {
		if *sr == *want {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("did not find %+v in results:", want)
		for _, r := range sreqs {
			t.Logf("  %+v", r)
		}
	}
}
