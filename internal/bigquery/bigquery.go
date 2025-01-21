// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package bigquery provides a client for reading and writing to BigQuery.
package bigquery

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	bq "cloud.google.com/go/bigquery"
	"cloud.google.com/go/civil"
	"golang.org/x/pkgsite-metrics/internal/derrors"
	"golang.org/x/pkgsite-metrics/internal/log"
	"google.golang.org/api/googleapi"
	"google.golang.org/api/iterator"
)

// Client is a client for connecting to BigQuery.
type Client struct {
	client               *bq.Client
	dataset              *bq.Dataset
	deleteDatasetOnClose bool
}

// NewClientCreate creates a new client for connecting to BigQuery, referring
// to a single dataset. It creates the dataset if it doesn't exist.
func NewClientCreate(ctx context.Context, projectID, datasetID string) (_ *Client, err error) {
	if err := CreateDataset(ctx, projectID, datasetID); err != nil {
		return nil, err
	}
	return newClient(ctx, projectID, datasetID)
}

func newClient(ctx context.Context, projectID, datasetID string) (_ *Client, err error) {
	defer derrors.Wrap(&err, "New(ctx, %q, %q)", projectID, datasetID)
	client, err := bq.NewClient(ctx, projectID)
	if err != nil {
		return nil, err
	}
	dataset := client.DatasetInProject(projectID, datasetID)
	// Check that the dataset exists and is accessible.
	if _, err := dataset.Metadata(ctx); err != nil {
		return nil, err
	}
	return &Client{
		client:  client,
		dataset: dataset,
	}, nil
}

func (c *Client) Close() (err error) {
	if c.deleteDatasetOnClose {
		err = c.dataset.DeleteWithContents(context.Background())
	}
	return errors.Join(err, c.client.Close())
}

// NewClientForTesting creates a client with a new, unique dataset. Closing the client deletes the dataset.
func NewClientForTesting(ctx context.Context, projectID, testID string) (*Client, error) {
	dsID := fmt.Sprintf("test_%s_%s", testID, time.Now().Format("20060102T030405"))
	c, err := NewClientCreate(ctx, projectID, dsID)
	if err != nil {
		return nil, err
	}
	c.deleteDatasetOnClose = true
	return c, nil
}

// CreateDataset creates a BigQuery dataset if it does not already exist.
func CreateDataset(ctx context.Context, projectID, datasetID string) (err error) {
	defer derrors.Wrap(&err, "CreateDataset(%q, %q)", projectID, datasetID)
	client, err := bq.NewClient(ctx, projectID)
	if err != nil {
		return err
	}
	dataset := client.DatasetInProject(projectID, datasetID)
	// If the dataset exists, do not try to create it. This will
	// avoid generating confusing error messages in logs.
	if _, err := dataset.Metadata(ctx); err != nil {
		if !isNotFoundError(err) {
			return err
		}
	} else {
		return nil
	}
	err = dataset.Create(ctx, &bq.DatasetMetadata{Name: datasetID})
	if err != nil && !isAlreadyExistsError(err) {
		// check already-exists error for sanity and in case of races
		return err
	}
	return nil
}

// isNotFoundError reports whether the error, which should come from a cloud.google.com/go/bigquery
// client call, is a NotFound error.
func isNotFoundError(err error) bool {
	return hasCode(err, http.StatusNotFound)
}

func isAlreadyExistsError(err error) bool {
	// The BigQuery API uses 409 for something that exists.
	return hasCode(err, http.StatusConflict)
}

func isRaceChangeError(err error) bool {
	// Changing the table in between update calls will make the
	// Etag invalid and result in a PreconditionFailed error.
	return hasCode(err, http.StatusPreconditionFailed)
}

func hasCode(err error, code int) bool {
	var gerr *googleapi.Error
	if !errors.As(err, &gerr) {
		return false
	}
	return gerr.Code == code
}

// Dataset returns the underlying client dataset.
func (c *Client) Dataset() *bq.Dataset {
	return c.dataset
}

// Table returns a handle for the given tableID in the client's dataset.
func (c *Client) Table(tableID string) *bq.Table {
	return c.dataset.Table(tableID)
}

// FullTableName returns the fully-qualified name of the table, suitable for
// use in queries.
func (c *Client) FullTableName(tableID string) string {
	// From https://github.com/googleapis/google-cloud-go/blob/bigquery/v1.43.0/bigquery/table.go#L544.
	return fmt.Sprintf("%s.%s.%s", c.dataset.ProjectID, c.dataset.DatasetID, tableID)
}

// CreateOrUpdateTable creates a table if it does not exist, or updates it if it does.
// It returns true if it created the table.
func (c *Client) CreateOrUpdateTable(ctx context.Context, tableID string) (created bool, err error) {
	defer derrors.Wrap(&err, "CreateOrUpdateTable(%q)", tableID)
	schema := TableSchema(tableID)
	if schema == nil {
		return false, fmt.Errorf("no schema registered for table %q", tableID)
	}

	meta, err := c.Table(tableID).Metadata(ctx) // check if the table already exists
	if err != nil {
		if !isNotFoundError(err) {
			return false, err
		}
		return true, c.Table(tableID).Create(ctx, &bq.TableMetadata{Schema: schema})
	}

	if SchemaVersion(schema) == SchemaVersion(meta.Schema) {
		// The schemas are the same, so we don't need to do anything. In fact, any
		// update, even an idempotent one, will result in table patching that counts
		// towards quota limits for table metadata updates.
		return false, nil
	}

	_, err = c.Table(tableID).Update(ctx, bq.TableMetadataToUpdate{Schema: schema}, meta.ETag)
	// There is a race condition if multiple threads of control call this function concurrently:
	// The table may have changed since Metadata was called above. This error is harmless: it
	// just means that someone else updated the table before us. Ignore it.
	if isAlreadyExistsError(err) || isRaceChangeError(err) {
		// check already-exists error for sanity and in case of races
		return false, nil
	}
	return false, err
}

// A Row is something that can be uploaded to BigQuery.
type Row interface {
	SetUploadTime(time.Time)
}

// Upload inserts a row into the table.
func (c *Client) Upload(ctx context.Context, tableID string, row Row) (err error) {
	defer derrors.Wrap(&err, "Upload(ctx, %q)", tableID)
	u := c.Table(tableID).Inserter()
	row.SetUploadTime(time.Now())
	return u.Put(ctx, row)
}

// UploadMany inserts multiple rows into the table.
// Each row should be a struct pointer.
// The chunkSize parameter limits the number of rows sent in a single request; this may
// be necessary to avoid reaching the maximum size of a request.
// If chunkSize is <= 0, all rows will be sent in one request.
func UploadMany[T Row](ctx context.Context, client *Client, tableID string, rows []T, chunkSize int) (err error) {
	defer derrors.Wrap(&err, "UploadMany(%q), %d rows, chunkSize=%d", tableID, len(rows), chunkSize)

	now := time.Now()
	// Set upload time.
	for _, r := range rows {
		r.SetUploadTime(now)
	}

	ins := client.Table(tableID).Inserter()
	if chunkSize <= 0 {
		return ins.Put(ctx, rows)
	}
	start := 0
	for start < len(rows) {
		end := start + chunkSize
		if end > len(rows) {
			end = len(rows)
		}
		for {
			log.Infof(ctx, "bigquery.UploadMany: uploading rows[%d:%d]", start, end)
			if err := ins.Put(ctx, rows[start:end]); err == nil {
				break
			} else if hasCode(err, http.StatusRequestEntityTooLarge) && end-start > 1 {
				// Request too large; reduce this chunk size by half.
				end = start + (end-start)/2
				continue
			} else {
				return err
			}
		}
		start = end
	}
	return nil
}

// ForEachRow calls f for each row in the given iterator.
// It returns as soon as f returns false.
func ForEachRow[T any](iter *bq.RowIterator, f func(*T) bool) error {
	for {
		var row T
		err := iter.Next(&row)
		if err == iterator.Done {
			break
		}
		if err != nil {
			return err
		}
		if !f(&row) {
			break
		}
	}
	return nil
}

// All returns all rows returned by iter.
func All[T any](iter *bq.RowIterator) ([]*T, error) {
	var ts []*T
	err := ForEachRow(iter, func(t *T) bool {
		ts = append(ts, t)
		return true
	})
	if err != nil {
		return nil, err
	}
	return ts, nil
}

func (c *Client) Query(ctx context.Context, q string) (*bq.RowIterator, error) {
	return c.client.Query(q).Read(ctx)
}

// NullFloat constructs a bq.NullFloat64
func NullFloat(f float64) bq.NullFloat64 {
	return bq.NullFloat64{Float64: f, Valid: true}
}

// NullString constructs a bq.NullString.
func NullString(s string) bq.NullString {
	return bq.NullString{StringVal: s, Valid: true}
}

// NullInt constructs a bq.NullInt.
func NullInt(i int) bq.NullInt64 {
	return bq.NullInt64{Int64: int64(i), Valid: true}
}

// NullTime constructs a bq.NullTime.
func NullTime(t time.Time) bq.NullTime {
	return bq.NullTime{Time: civil.TimeOf(t), Valid: true}
}

// SchemaVersion computes a relatively short string from a schema, such that
// different schemas result in different strings with high probability.
func SchemaVersion(schema bq.Schema) string {
	hash := sha256.Sum256([]byte(SchemaString(schema)))
	return hex.EncodeToString(hash[:])
}

// SchemaString returns a long, human-readable string summarizing schema.
func SchemaString(schema bq.Schema) string {
	var b strings.Builder

	// Order of columns does not matter in relational algebra,
	// so we sort them by column name.
	var fields []*bq.FieldSchema
	for _, f := range schema {
		fields = append(fields, f)
	}
	sort.SliceStable(fields, func(i, j int) bool {
		return fields[i].Name < fields[j].Name // fields cannot have the same name
	})

	for i, field := range fields {
		if i > 0 {
			b.WriteRune(';')
		}
		b.WriteString(field.Name)
		if field.Repeated {
			b.WriteString(",rep")
		}
		if field.Required {
			b.WriteString(",req")
		}
		b.WriteByte(':')
		if field.Type == bq.RecordFieldType {
			fmt.Fprintf(&b, "(%s)", SchemaString(field.Schema))
		} else {
			b.WriteString(string(field.Type))
		}
	}
	return b.String()
}

var (
	tableMu sync.Mutex
	tables  = map[string]bq.Schema{}
)

// AddTable records the schema for a table, so table creation just needs the name.
func AddTable(tableID string, s bq.Schema) {
	tableMu.Lock()
	defer tableMu.Unlock()
	tables[tableID] = s
}

// TableSchema returns the schema associated with the given table,
// or nil if there is none.
func TableSchema(tableID string) bq.Schema {
	tableMu.Lock()
	defer tableMu.Unlock()
	return tables[tableID]
}

// PartitionQuery describes a query that returns one row for each distinct value
// of the partition columns in the given table.
//
// The selected row will be the first one according to the OrderBy clauses.
//
// For example, say the students table holds student names and classes.
// Then
//
//	  PartitionQuery{
//		   Table: "students",
//		   PartitionOn: "class",
//		   OrderBy: "name ASC",
//		 }.String()
//
// will construct a query returning the student in each class whose name is
// alphabetically first.
//
// (BigQuery SQL has no DISTINCT ON feature and doesn't allow columns of type RECORD
// in queries with DISTINCT, so we have to take this approach.)
type PartitionQuery struct {
	From        string // should use full table name
	Columns     string // comma-separated columns to select, or "*" ("" => "*")
	PartitionOn string // comma-separated columns defining the partition
	Where       string // WHERE clause
	OrderBy     string // text after ORDER BY: comma-separated columns, each
	// optionally followed by DESC or ASC
}

func (q PartitionQuery) String() string {
	// This query first organizes the table rows into windows that have the same partitionColumn.
	// The rows in each window are sorted by the given orderings.
	// They are then assigned numbers, where 1 is the first row in the window.
	// Finally, only the first row in each window is chosen.
	// (ROW_NUMBER guarantees that each row has a distinct number; RANK assigns the
	// same number to identical rows, which means that the result may still contain
	// duplicates.)
	const qf = `
		SELECT * EXCEPT (rownum)
		FROM (
			SELECT %s, ROW_NUMBER() OVER (
				PARTITION BY %s
				ORDER BY %s
			) AS rownum
			FROM %s
			%s
		) WHERE rownum = 1
	`
	cols := q.Columns
	if cols == "" {
		cols = "*"
	}
	where := q.Where
	if where != "" {
		where = "WHERE " + where
	}
	return fmt.Sprintf(qf, cols, q.PartitionOn, q.OrderBy, q.From, where)
}

// InferSchema is a copy of cloud.google.com/go/bigquery.InferSchema so
// users don't have to import cloud.google.com/go/bigquery just to get it.
var InferSchema = bq.InferSchema
