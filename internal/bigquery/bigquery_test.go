// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package bigquery

import (
	"context"
	"testing"

	bq "cloud.google.com/go/bigquery"
	test "golang.org/x/pkgsite-metrics/internal/testing"
)

func TestIsNotFoundError(t *testing.T) {
	test.NeedsIntegrationEnv(t)

	client, err := bq.NewClient(context.Background(), "go-ecosystem")
	if err != nil {
		t.Fatal(err)
	}
	dataset := client.Dataset("nope")
	_, err = dataset.Metadata(context.Background())
	if !isNotFoundError(err) {
		t.Errorf("got false, want true for %v", err)
	}
}
