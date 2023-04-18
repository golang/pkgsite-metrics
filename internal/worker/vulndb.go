// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package worker

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"cloud.google.com/go/storage"
	"golang.org/x/vuln/osv"
	"google.golang.org/api/iterator"
)

// gcsOSVPrefix is the directory under which .json
// files with OSV entries are located.
const gcsOSVPrefix = "ID"

// allVulnerabilities fetches all osv.Entries from GCS bucket located at ID/*.json paths.
func allVulnerabilities(ctx context.Context, bucket *storage.BucketHandle) ([]*osv.Entry, error) {
	var entries []*osv.Entry
	query := &storage.Query{Prefix: gcsOSVPrefix}
	it := bucket.Objects(ctx, query)
	for {
		attrs, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, err
		}
		// Skip zip files and index.json.
		if !strings.HasSuffix(attrs.Name, ".json") || strings.HasSuffix(attrs.Name, "index.json") {
			continue
		}

		e, err := readEntry(ctx, bucket, attrs.Name)
		if err != nil {
			return nil, err
		}
		entries = append(entries, e)
	}
	return entries, nil
}

func readEntry(ctx context.Context, bucket *storage.BucketHandle, gcsPath string) (*osv.Entry, error) {
	localPath := filepath.Join(os.TempDir(), "binary")
	if err := copyToLocalFile(localPath, false, gcsPath, gcsOpenFileFunc(ctx, bucket)); err != nil {
		return nil, err
	}
	js, err := os.ReadFile(localPath)
	if err != nil {
		return nil, err
	}
	var entry osv.Entry
	if err := json.Unmarshal(js, &entry); err != nil {
		return nil, err
	}
	return &entry, nil
}
