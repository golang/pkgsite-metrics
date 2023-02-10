// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package queue

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/pkgsite-metrics/internal/config"
	taskspb "google.golang.org/genproto/googleapis/cloud/tasks/v2"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/durationpb"
)

type testTask struct {
	name   string
	path   string
	params string
}

func (t *testTask) Name() string   { return t.name }
func (t *testTask) Path() string   { return t.path }
func (t *testTask) Params() string { return t.params }

func TestNewTaskID(t *testing.T) {
	for _, test := range []struct {
		name, path, params string
		want               string
	}{
		{
			"m@v1.2", "path", "params",
			"m_v1_2-ns-31026413",
		},
		{
			"µπΩ/github.com@v2.3.4-ß", "p", "",
			"_00b5_03c0_03a9_-github_com_v2_3_4-_00df-ns-148de9c5",
		},
	} {
		tt := &testTask{test.name, test.path, test.params}
		got := newTaskID("ns", tt)
		if got != test.want {
			t.Errorf("%v: got %s, want %s", tt, got, test.want)
		}
	}
}

func TestNewTaskRequest(t *testing.T) {
	cfg := config.Config{
		ProjectID:      "Project",
		LocationID:     "us-central1",
		QueueURL:       "http://1.2.3.4:8000",
		ServiceAccount: "sa",
	}
	want := &taskspb.CreateTaskRequest{
		Parent: "projects/Project/locations/us-central1/queues/queueID",
		Task: &taskspb.Task{
			DispatchDeadline: durationpb.New(maxCloudTasksTimeout),
			MessageType: &taskspb.Task_HttpRequest{
				HttpRequest: &taskspb.HttpRequest{
					HttpMethod: taskspb.HttpMethod_POST,
					Url:        "http://1.2.3.4:8000/test/scan/mod@v1.2.3?importedby=0&mode=test&insecure=true",
					AuthorizationHeader: &taskspb.HttpRequest_OidcToken{
						OidcToken: &taskspb.OidcToken{
							ServiceAccountEmail: "sa",
						},
					},
				},
			},
		},
	}
	gcp, err := newGCP(&cfg, nil, "queueID")
	if err != nil {
		t.Fatal(err)
	}
	opts := &Options{
		Namespace:      "test",
		TaskNameSuffix: "suf",
	}
	sreq := &testTask{
		name:   "name",
		path:   "mod@v1.2.3",
		params: "importedby=0&mode=test&insecure=true",
	}
	got, err := gcp.newTaskRequest(sreq, opts)
	if err != nil {
		t.Fatal(err)
	}
	want.Task.Name = got.Task.Name
	if diff := cmp.Diff(want, got, protocmp.Transform()); diff != "" {
		t.Errorf("mismatch (-want, +got):\n%s", diff)
	}

	opts.DisableProxyFetch = true
	want.Task.MessageType.(*taskspb.Task_HttpRequest).HttpRequest.Url += "&proxyfetch=off"
	got, err = gcp.newTaskRequest(sreq, opts)
	if err != nil {
		t.Fatal(err)
	}
	want.Task.Name = got.Task.Name
	if diff := cmp.Diff(want, got, protocmp.Transform()); diff != "" {
		t.Errorf("mismatch (-want, +got):\n%s", diff)
	}

}
