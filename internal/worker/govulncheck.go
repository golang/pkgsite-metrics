// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package worker

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/pkgsite-metrics/internal"
	"golang.org/x/pkgsite-metrics/internal/derrors"
	"golang.org/x/pkgsite-metrics/internal/govulncheck"
	"golang.org/x/pkgsite-metrics/internal/log"
)

type GovulncheckServer struct {
	*Server
	storedWorkStates map[[2]string]*govulncheck.WorkState
	workVersion      *govulncheck.WorkVersion
}

func newGovulncheckServer(s *Server) *GovulncheckServer {
	return &GovulncheckServer{
		Server:           s,
		storedWorkStates: make(map[[2]string]*govulncheck.WorkState),
	}
}

func (h *GovulncheckServer) getWorkVersion(ctx context.Context) (_ *govulncheck.WorkVersion, err error) {
	defer derrors.Wrap(&err, "GovulncheckServer.getWorkVersion")
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.workVersion == nil {
		lmt, err := dbLastModified(h.cfg.VulnDBDir)
		if err != nil {
			return nil, err
		}
		goEnv, err := internal.GoEnv()
		if err != nil {
			return nil, err
		}
		h.workVersion = &govulncheck.WorkVersion{
			GoVersion:          goEnv["GOVERSION"],
			VulnDBLastModified: lmt,
			WorkerVersion:      h.cfg.VersionID,
			SchemaVersion:      govulncheck.SchemaVersion,
		}
		log.Infof(ctx, "govulncheck work version: %+v", h.workVersion)
	}
	return h.workVersion, nil
}

// dbLastModified computes the last modified time stamp of
// vulnerability database rooted at vulnDB.
//
// Follows the logic of golang.org/x/internal/client/client.go:Client.LastModifiedTime.
func dbLastModified(vulnDB string) (time.Time, error) {
	dbFile := filepath.Join(vulnDB, "index/db.json")
	b, err := os.ReadFile(dbFile)
	if err != nil {
		return time.Time{}, err
	}

	// dbMeta contains metadata about the database itself.
	//
	// Copy of golang.org/x/internal/client/schema.go:dbMeta.
	type dbMeta struct {
		// Modified is the time the database was last modified, calculated
		// as the most recent time any single OSV entry was modified.
		Modified time.Time `json:"modified"`
	}

	var dbm dbMeta
	if err := json.Unmarshal(b, &dbm); err != nil {
		return time.Time{}, err
	}

	return dbm.Modified, nil
}
