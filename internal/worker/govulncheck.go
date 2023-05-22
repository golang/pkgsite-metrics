// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package worker

import (
	"context"
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

func newGovulncheckServer(ctx context.Context, s *Server) (*GovulncheckServer, error) {
	var (
		swv map[[2]string]*govulncheck.WorkState
		err error
	)
	if s.bqClient != nil {
		swv, err = govulncheck.ReadWorkStates(ctx, s.bqClient)
		if err != nil {
			return nil, err
		}
		log.Infof(ctx, "read %d work versions", len(swv))
	}
	return &GovulncheckServer{
		Server:           s,
		storedWorkStates: swv,
	}, nil
}

func (h *GovulncheckServer) getWorkVersion(ctx context.Context) (_ *govulncheck.WorkVersion, err error) {
	defer derrors.Wrap(&err, "GovulncheckServer.getWorkVersion")
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.workVersion == nil {
		lmt := time.Now() // TODO: Implement this
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
