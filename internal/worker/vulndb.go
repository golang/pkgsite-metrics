// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package worker

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"fmt"
	"net/http"

	"cloud.google.com/go/storage"
	"golang.org/x/vuln/osv"
	"google.golang.org/api/iterator"

	"golang.org/x/pkgsite-metrics/internal"
	"golang.org/x/pkgsite-metrics/internal/bigquery"
	"golang.org/x/pkgsite-metrics/internal/derrors"
	"golang.org/x/pkgsite-metrics/internal/log"
	"golang.org/x/pkgsite-metrics/internal/vulndb"
	"golang.org/x/pkgsite-metrics/internal/vulndbreqs"
)

func (s *Server) handleComputeRequests(w http.ResponseWriter, r *http.Request) (err error) {
	defer derrors.Wrap(&err, "handleComputeRequests")

	ctx := r.Context()
	// Don't use the Server's BigQuery client: it's for the wrong
	// dataset.
	vClient, err := bigquery.NewClientCreate(ctx, s.cfg.ProjectID, vulndbreqs.DatasetName)
	if err != nil {
		return err
	}
	keyName := "projects/" + s.cfg.ProjectID + "/secrets/vulndb-hmac-key"
	hmacKey, err := internal.GetSecret(ctx, keyName)
	if err != nil {
		return err
	}
	err = vulndbreqs.ComputeAndStore(ctx, s.cfg.VulnDBBucketProjectID, vClient, []byte(hmacKey))
	if err != nil {
		return err
	}
	fmt.Fprintf(w, "Successfully computed and stored request counts.\n")
	return nil
}

func (s *Server) handleVulnDB(w http.ResponseWriter, r *http.Request) (err error) {
	defer derrors.Wrap(&err, "handleVulnDB")

	ctx := r.Context()
	dbClient, err := bigquery.NewClientCreate(ctx, s.cfg.ProjectID, vulndb.DatasetName)
	if err != nil {
		return err
	}

	c, err := storage.NewClient(ctx)
	if err != nil {
		return err
	}
	bucket := c.Bucket("go-vulndb")
	if bucket == nil {
		return errors.New("failed to create go-vulndb bucket")
	}

	lmts, err := lastModified(ctx, dbClient)
	if err != nil {
		return err
	}
	entries, err := vulndbEntries(ctx, bucket)
	if err != nil {
		return err
	}

	for _, e := range entries {
		lmt, ok := lmts[e.ID]
		if ok && e.ModifiedTime.Equal(lmt) {
			// Skip adding the entry if nothing has changed in the meantime.
			log.Infof(ctx, "skipping entry %s, it has not been modified", e.ID)
			continue
		}
		if err = writeResult(ctx, false, w, dbClient, vulndb.TableName, e); err != nil {
			return err
		}
	}

	return nil
}

func vulndbEntries(ctx context.Context, bucket *storage.BucketHandle) ([]*vulndb.Entry, error) {
	osvEntries, err := allVulnerabilities(ctx, bucket)
	if err != nil {
		return nil, err
	}
	var entries []*vulndb.Entry
	for _, oe := range osvEntries {
		entries = append(entries, vulndb.Convert(oe))
	}
	return entries, nil
}

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

func lastModified(ctx context.Context, c *bigquery.Client) (map[string]time.Time, error) {
	es, err := vulndb.ReadMostRecentDB(ctx, c)
	if err != nil {
		return nil, err
	}
	m := make(map[string]time.Time)
	for _, e := range es {
		m[e.ID] = e.ModifiedTime
	}
	return m, nil
}
