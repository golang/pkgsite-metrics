// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package worker

import (
	"fmt"
	"net/http"

	"golang.org/x/pkgsite-metrics/internal/pkgsitedb"
)

func (s *Server) handleTestDB(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	db, err := pkgsitedb.Open(ctx, s.cfg)
	if err != nil {
		return err
	}
	specs, err := pkgsitedb.ModuleSpecs(ctx, db, 100)
	if err != nil {
		return err
	}
	fmt.Fprintf(w, "got %d modules with over 100 importers", len(specs))
	return nil
}
