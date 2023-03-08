// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package govulncheck

import (
	"encoding/json"
	"errors"

	"golang.org/x/vuln/exp/govulncheck"
)

// ScanStats represent monitoring information about a given
// run of govulncheck or vulncheck
type ScanStats struct {
	// The amount of time a scan took to run, in seconds
	ScanSeconds float64
	// The peak (heap) memory used by govulncheck, in kb
	ScanMemory uint64
}

// GovulncheckResponse passes both the raw govulncheck result as well as
// statistics about memory usage and run time
type GovulncheckResponse struct {
	Res   govulncheck.Result
	Stats ScanStats
}

func UnmarshalGovulncheckSandboxResponse(output []byte) (*GovulncheckResponse, error) {
	var e struct{ Error string }
	if err := json.Unmarshal(output, &e); err != nil {
		return nil, err
	}
	if e.Error != "" {
		return nil, errors.New(e.Error)
	}
	var res GovulncheckResponse
	if err := json.Unmarshal(output, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

func UnmarshalGovulncheckResult(output []byte) (*govulncheck.Result, error) {
	var e struct {
		Error string
	}
	if err := json.Unmarshal(output, &e); err != nil {
		return nil, err
	}
	if e.Error != "" {
		return nil, errors.New(e.Error)
	}
	var res govulncheck.Result
	if err := json.Unmarshal(output, &res); err != nil {
		return nil, err
	}
	return &res, nil
}
