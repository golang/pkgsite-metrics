// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package bigquery

import (
	"context"
	"strings"
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

func TestPartitionQuery(t *testing.T) {
	// Remove newlines and extra white
	clean := func(s string) string {
		return strings.Join(strings.Fields(s), " ")
	}

	for i, test := range []struct {
		q    PartitionQuery
		want string
	}{
		{
			PartitionQuery{
				From:        "full.table",
				Columns:     "*",
				PartitionOn: "p",
				OrderBy:     "o",
			},
			`SELECT * EXCEPT (rownum)
				 FROM ( SELECT *, ROW_NUMBER() OVER ( PARTITION BY p ORDER BY o ) AS rownum
				 FROM full.table ) WHERE rownum  = 1`,
		},
		{
			PartitionQuery{
				From:        "full.table",
				Columns:     "a, b, c",
				PartitionOn: "p",
				OrderBy:     "o",
				Where:       "name = 'foo' AND args = 'bar baz'",
			},
			`SELECT * EXCEPT (rownum)
				 FROM ( SELECT a, b, c, ROW_NUMBER() OVER ( PARTITION BY p ORDER BY o ) AS rownum
				 FROM full.table
				 WHERE name = 'foo' AND args = 'bar baz'
				) WHERE rownum  = 1`,
		},
	} {
		got := clean(test.q.String())
		want := clean(test.want)
		if got != want {
			t.Errorf("#%d:\ngot  %s\nwant %s", i, got, want)
		}
	}
}

func TestSchemaString(t *testing.T) {
	type nest struct {
		N []byte
		M float64
	}

	type s struct {
		A string
		B int
		C []bool
		D nest
	}
	const want = "A,req:STRING;B,req:INTEGER;C,rep:BOOLEAN;D,req:(M,req:FLOAT;N,req:BYTES)"
	schema, err := InferSchema(s{})
	if err != nil {
		t.Fatal(err)
	}
	got := SchemaString(schema)
	if got != want {
		t.Errorf("\ngot  %q\nwant %q", got, want)
	}

	// The order of fields should not matter
	type p struct {
		A string
		D nest
		C []bool
		B int
	}

	schema, err = InferSchema(p{})
	if err != nil {
		t.Fatal(err)
	}
	got = SchemaString(schema)
	if got != want {
		t.Errorf("\ngot  %q\nwant %q", got, want)
	}
}
