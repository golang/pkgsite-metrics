// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package queue

import (
	"testing"

	taskspb "cloud.google.com/go/cloudtasks/apiv2/cloudtaskspb"
	"github.com/google/go-cmp/cmp"
	"golang.org/x/pkgsite-metrics/internal/config"
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
	queueIDs := []string{"queueID-0", "queueID-1", "queueID-2", "queueID-3"}
	var possibleQueueNames []string
	for _, qID := range queueIDs {
		possibleQueueNames = append(possibleQueueNames, "projects/Project/locations/us-central1/queues/"+qID)
	}

	gcp, err := newGCP(&cfg, nil, queueIDs)
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

	validParent := false
	for _, pqn := range possibleQueueNames {
		if got.Parent == pqn {
			validParent = true
			break
		}
	}
	if !validParent {
		t.Errorf("got.Parent = %q, want one of %v", got.Parent, possibleQueueNames)
	}

	want := &taskspb.CreateTaskRequest{
		Parent: got.Parent,
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

	validParent = false
	for _, pqn := range possibleQueueNames {
		if got.Parent == pqn {
			validParent = true
			break
		}
	}
	if !validParent {
		t.Errorf("got.Parent = %q, want one of %v", got.Parent, possibleQueueNames)
	}
	want.Parent = got.Parent

	if diff := cmp.Diff(want, got, protocmp.Transform()); diff != "" {
		t.Errorf("mismatch (-want, +got):\n%s", diff)
	}
}
