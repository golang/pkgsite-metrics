// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package worker

import (
	"context"
	"errors"
	"fmt"
	"runtime/debug"

	"golang.org/x/pkgsite-metrics/internal/derrors"
	"golang.org/x/pkgsite-metrics/internal/log"
	ivulncheck "golang.org/x/pkgsite-metrics/internal/vulncheck"
)

type VulncheckServer struct {
	*Server
	storedWorkVersions map[[2]string]*ivulncheck.WorkVersion
	workVersion        *ivulncheck.WorkVersion
}

func newVulncheckServer(ctx context.Context, s *Server) (*VulncheckServer, error) {
	var (
		swv map[[2]string]*ivulncheck.WorkVersion
		err error
	)
	if s.bqClient != nil {
		swv, err = ivulncheck.ReadWorkVersions(ctx, s.bqClient)
		if err != nil {
			return nil, err
		}
		log.Infof(ctx, "read %d work versions", len(swv))
	}
	return &VulncheckServer{
		Server:             s,
		storedWorkVersions: swv,
	}, nil
}

func (h *VulncheckServer) getWorkVersion(ctx context.Context) (_ *ivulncheck.WorkVersion, err error) {
	defer derrors.Wrap(&err, "VulncheckServer.getWorkVersion")
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.workVersion == nil {
		lmt, err := h.vulndbClient.LastModifiedTime(ctx)
		if err != nil {
			return nil, err
		}
		vulnVersion, err := readVulnVersion()
		if err != nil {
			return nil, err
		}
		h.workVersion = &ivulncheck.WorkVersion{
			VulnDBLastModified: lmt,
			WorkerVersion:      h.cfg.VersionID,
			SchemaVersion:      ivulncheck.SchemaVersion,
			VulnVersion:        vulnVersion,
		}
		log.Infof(ctx, "vulncheck work version: %+v", h.workVersion)
	}
	return h.workVersion, nil
}

// readVulnVersion returns the version of the golang.org/x/vuln module linked into
// the current binary.
func readVulnVersion() (string, error) {
	const modulePath = "golang.org/x/vuln"
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "", errors.New("vuln version not available")
	}
	for _, mod := range info.Deps {
		if mod.Path == modulePath {
			if mod.Replace != nil {
				mod = mod.Replace
			}
			return mod.Version, nil
		}
	}
	return "", fmt.Errorf("module %s not found", modulePath)
}
