// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package worker

import (
	"context"
	"flag"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/pkgsite-metrics/internal/config"
	"golang.org/x/pkgsite-metrics/internal/queue"
	"golang.org/x/pkgsite-metrics/internal/scan"
)

var binaryBucket = flag.String("binary-bucket", "", "bucket for scannable binaries")

func TestReadBinaries(t *testing.T) {
	if *binaryBucket == "" {
		t.Skip("missing -binary-bucket")
	}
	sreqs, err := readBinaries(context.Background(), *binaryBucket)
	if err != nil {
		t.Fatal(err)
	}
	want := &vulncheckRequest{
		scan.ModuleURLPath{
			Module:  "golang.org/x/pkgsite",
			Version: "v0.0.0-20221004150836-873fb37c2479",
			Suffix:  "cmd/worker",
		},
		vulncheckRequestParams{Mode: ModeBinary},
	}
	found := false
	for _, sr := range sreqs {
		if *sr == *want {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("did not find %+v in results:", want)
		for _, r := range sreqs {
			t.Logf("  %+v", r)
		}
	}
}

func TestCreateQueueTasks(t *testing.T) {
	vreq := func(path, version, mode string, importedBy int) *vulncheckRequest {
		return &vulncheckRequest{
			scan.ModuleURLPath{Module: path, Version: version},
			vulncheckRequestParams{Mode: mode, ImportedBy: importedBy},
		}
	}

	params := &vulncheckEnqueueParams{Min: 8, File: "testdata/modules.txt"}
	gotTasks, err := createVulncheckQueueTasks(context.Background(), &config.Config{}, params, []string{ModeVTAStacks})
	if err != nil {
		t.Fatal(err)
	}

	wantTasks := []queue.Task{
		vreq("github.com/pkg/errors", "v0.9.1", ModeVTAStacks, 10),
		vreq("golang.org/x/net", "v0.4.0", ModeVTAStacks, 20),
	}
	if diff := cmp.Diff(wantTasks, gotTasks, cmp.AllowUnexported(vulncheckRequest{})); diff != "" {
		t.Errorf("mismatch (-want, +got):\n%s", diff)
	}

	allModes, err := listModes("", true)
	if err != nil {
		t.Fatal(err)
	}
	gotTasks, err = createVulncheckQueueTasks(context.Background(), &config.Config{}, params, allModes)
	if err != nil {
		t.Fatal(err)
	}
	wantTasks = nil
	// cfg.BinaryBucket is empty, so no binary-mode tasks are created.
	for _, mode := range []string{ModeGovulncheck, ModeImports, ModeVTAStacks} {
		wantTasks = append(wantTasks,
			vreq("github.com/pkg/errors", "v0.9.1", mode, 10),
			vreq("golang.org/x/net", "v0.4.0", mode, 20))
	}

	if diff := cmp.Diff(wantTasks, gotTasks, cmp.AllowUnexported(vulncheckRequest{})); diff != "" {
		t.Errorf("mismatch (-want, +got):\n%s", diff)
	}
}

func TestListModes(t *testing.T) {
	for _, test := range []struct {
		param   string
		all     bool
		want    []string
		wantErr bool
	}{
		{"", true, []string{ModeBinary, ModeGovulncheck, ModeImports, ModeVTAStacks}, false},
		{"", false, []string{ModeVTAStacks}, false},
		{"imports", false, []string{ModeImports}, false},
		{"imports", true, nil, true},
	} {
		t.Run(fmt.Sprintf("%q,%t", test.param, test.all), func(t *testing.T) {
			got, err := listModes(test.param, test.all)
			if err != nil && !test.wantErr {
				t.Fatal(err)
			}
			if err == nil && !cmp.Equal(got, test.want) {
				t.Errorf("got %v, want %v", got, test.want)
			}
		})
	}
}
