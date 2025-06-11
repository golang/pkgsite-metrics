// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !plan9

// Package pkgsitedb provides functionality for connecting to the pkgsite
// database.
package pkgsitedb

import (
	"context"
	"database/sql"
	"fmt"
	"regexp"

	_ "github.com/lib/pq"

	"golang.org/x/pkgsite-metrics/internal"
	"golang.org/x/pkgsite-metrics/internal/config"
	"golang.org/x/pkgsite-metrics/internal/derrors"
	"golang.org/x/pkgsite-metrics/internal/scan"
)

// Open creates a connection to the pkgsite database.
func Open(ctx context.Context, cfg *config.Config) (_ *sql.DB, err error) {
	defer derrors.Wrap(&err, "Open")
	password, err := internal.GetSecret(ctx, cfg.PkgsiteDBSecret)
	if err != nil {
		return nil, err
	}
	connString := fmt.Sprintf(
		"user='%s' password='%s' host='%s' port=%s dbname='%s' sslmode='disable'",
		cfg.PkgsiteDBUser, password, cfg.PkgsiteDBHost, cfg.PkgsiteDBPort, cfg.PkgsiteDBName)
	defer derrors.Wrap(&err, "openPkgsiteDB, connString=%q", redactPassword(connString))
	db, err := sql.Open("postgres", connString)
	if err != nil {
		return nil, err
	}
	if err := db.PingContext(ctx); err != nil {
		return nil, err
	}
	return db, nil
}

var passwordRegexp = regexp.MustCompile(`password=\S+`)

func redactPassword(dbinfo string) string {
	return passwordRegexp.ReplaceAllLiteralString(dbinfo, "password=REDACTED")
}

// ModuleSpecs retrieves all modules that contain packages that are
// imported by minImportedByCount or more packages.
// It looks for the information in the search_documents table of the given pkgsite DB.
func ModuleSpecs(ctx context.Context, db *sql.DB, minImports, maxImports int32) (specs []scan.ModuleSpec, err error) {
	defer derrors.Wrap(&err, "moduleSpecsFromDB")
	query := `
		SELECT module_path, version, max(imported_by_count)
		FROM search_documents
		GROUP BY module_path, version
		HAVING max(imported_by_count) >= $1 AND max(imported_by_count) <= $2
		ORDER BY max(imported_by_count) desc`
	rows, err := db.QueryContext(ctx, query, minImports, maxImports)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var spec scan.ModuleSpec
		if err := rows.Scan(&spec.Path, &spec.Version, &spec.ImportedBy); err != nil {
			return nil, err
		}
		specs = append(specs, spec)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return specs, nil
}
