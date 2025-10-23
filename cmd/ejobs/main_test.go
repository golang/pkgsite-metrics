// Copyright 2025 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"golang.org/x/pkgsite-metrics/internal/analysis"
	"golang.org/x/pkgsite-metrics/internal/bigquery"
	"google.golang.org/api/iterator"

	bq "cloud.google.com/go/bigquery"
)

type mockRowIterator struct {
	results []*analysis.Result
	index   int
}

func (it *mockRowIterator) Next(v interface{}) error {
	if it.index >= len(it.results) {
		return iterator.Done
	}
	res := it.results[it.index]
	val := v.(*analysis.Result)
	*val = *res
	it.index++
	return nil
}

type mockBQClient struct {
	expectedResults []*analysis.Result
}

func (c *mockBQClient) QueryWithParams(ctx context.Context, query string, params []bq.QueryParameter) (bigquery.RowIterator, error) {
	return &mockRowIterator{results: c.expectedResults}, nil
}

func (c *mockBQClient) FullTableName(tableID string) string { return "mock.table" }
func (c *mockBQClient) Close() error                        { return nil }

func TestFetchAndPrintResults(t *testing.T) {
	mockClient := &mockBQClient{
		expectedResults: []*analysis.Result{
			{ModulePath: "example.com/one", Version: "v1.0.0", CreatedAt: time.Now()},
			{ModulePath: "example.com/two", Version: "v1.2.3", CreatedAt: time.Now().Add(1 * time.Second)},
		},
	}
	var out bytes.Buffer
	var lastCreatedAt time.Time
	processedIDs := make(map[string]struct{})

	count, err := fetchAndPrintResults(context.Background(), &out, mockClient, "fake-job-id", lastCreatedAt, processedIDs)
	if err != nil {
		t.Fatalf("fetchAndPrintResults failed: %v", err)
	}

	if count != len(mockClient.expectedResults) {
		t.Errorf("expected to process %d new results, but got %d", len(mockClient.expectedResults), count)
	}
	got := out.String()
	for _, result := range mockClient.expectedResults {
		if !strings.Contains(got, result.ModulePath) {
			t.Errorf("output did not contain first result; got:\n%s, wanted:%s", got, result.ModulePath)
		}
		if !strings.Contains(got, result.Version) {
			t.Errorf("output did not contain first result; got:\n%s, wanted:%s", got, result.Version)
		}
	}

	if len(processedIDs) != len(mockClient.expectedResults) {
		t.Errorf("expected %d processed IDs, but got %d", len(mockClient.expectedResults), len(processedIDs))
	}
}
