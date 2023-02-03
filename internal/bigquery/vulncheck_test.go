// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package bigquery

import (
	"testing"

	bq "cloud.google.com/go/bigquery"
)

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
	const want = "A,req:STRING;B,req:INTEGER;C,rep:BOOLEAN;D,req:(N,req:BYTES;M,req:FLOAT)"
	schema, err := bq.InferSchema(s{})
	if err != nil {
		t.Fatal(err)
	}
	got := schemaString(schema)
	if got != want {
		t.Errorf("\ngot  %q\nwant %q", got, want)
	}
}
