// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !plan9

package pkgsitedb

import (
	// imported to register the postgres database driver
	"context"
	"database/sql"
	"flag"
	"fmt"
	"net/url"
	"strings"
	"testing"

	_ "github.com/lib/pq"
)

// dbInfo is -db flag used to test against a a local database (host 127.0.0.1).
var dbInfo = flag.String("db", "",
	"DB info for testing in the form 'name=NAME&port=PORT&user=USER&password=PW'")

func TestModuleSpecs(t *testing.T) {
	if *dbInfo == "" {
		t.Skip("missing -db")
	}
	info := map[string]string{}
	for _, kv := range strings.Split(*dbInfo, "&") {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			t.Fatalf("%q is not in the form 'key=value'", kv)
		}
		info[k] = v
	}

	const host = "127.0.0.1"

	ctx := context.Background()
	dbinfo := fmt.Sprintf("postgres://%s/%s?sslmode=disable&user=%s&password=%s&port=%s&timezone=UTC",
		host, info["name"], url.QueryEscape(info["user"]), url.QueryEscape(info["password"]),
		url.QueryEscape(info["port"]))
	db, err := sql.Open("postgres", dbinfo)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.PingContext(ctx); err != nil {
		t.Fatal(err)
	}
	got, err := ModuleSpecs(ctx, db, 1000)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("got %d module specs from %s", len(got), info["name"])
	if got, want := len(got), 100; got < want {
		t.Errorf("got %d results, expected at least %d", got, want)
	}
	for _, g := range got {
		fmt.Printf("%s  %s\n", g.Path, g.Version)
	}
}
