// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package worker

import (
	"context"
	"testing"

	"cloud.google.com/go/storage"
	test "golang.org/x/pkgsite-metrics/internal/testing"
)

func TestIntegrationAllVulns(t *testing.T) {
	test.NeedsIntegrationEnv(t)

	ctx := context.Background()
	c, err := storage.NewClient(ctx)
	if err != nil {
		t.Fatal(err)
	}
	bucket := c.Bucket("go-vulndb")
	if bucket == nil {
		t.Fatal("failed to create go-vulndb bucket")
	}
	es, err := allVulnerabilities(ctx, bucket)
	if err != nil {
		t.Fatal(err)
	}
	if len(es) == 0 {
		t.Fatal("want some vulnerabilities; got none")
	}
}
