// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package queue provides queue implementations that can be used for
// asynchronous scheduling of fetch actions.
package queue

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	cloudtasks "cloud.google.com/go/cloudtasks/apiv2"
	"golang.org/x/pkgsite-metrics/internal/config"
	"golang.org/x/pkgsite-metrics/internal/derrors"
	"golang.org/x/pkgsite-metrics/internal/log"
	taskspb "google.golang.org/genproto/googleapis/cloud/tasks/v2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"
)

// A Task can produce information needed for Cloud Tasks.
type Task interface {
	Name() string   // Human-readable string for the task. Need not be unique.
	Path() string   // URL path
	Params() string // URL query params
}

// A Queue provides an interface for asynchronous scheduling of fetch actions.
type Queue interface {
	// Enqueue a scan request.
	// Reports whether a new task was actually added.
	EnqueueScan(context.Context, Task, *Options) (bool, error)
}

// New creates a new Queue with name queueName based on the configuration
// in cfg. When running locally, Queue uses numWorkers concurrent workers.
func New(ctx context.Context, cfg *config.Config, processFunc inMemoryProcessFunc) (Queue, error) {
	if !config.OnCloudRun() {
		return NewInMemory(ctx, cfg.LocalQueueWorkers, processFunc), nil
	}
	client, err := cloudtasks.NewClient(ctx)
	if err != nil {
		return nil, err
	}
	g, err := newGCP(cfg, client, cfg.QueueName)
	if err != nil {
		return nil, err
	}
	log.Infof(ctx, "enqueuing at %s with queueURL=%q", g.queueName, g.queueURL)
	return g, nil
}

// GCP provides a Queue implementation backed by the Google Cloud Tasks
// API.
type GCP struct {
	client    *cloudtasks.Client
	queueName string // full GCP name of the queue
	queueURL  string // non-AppEngine URL to post tasks to
	// token holds information that lets the task queue construct an authorized request to the worker.
	// Since the worker sits behind the IAP, the queue needs an identity token that includes the
	// identity of a service account that has access, and the client ID for the IAP.
	// We use the service account of the current process.
	token *taskspb.HttpRequest_OidcToken
}

// NewGCP returns a new Queue that can be used to enqueue tasks using the
// cloud tasks API.  The given queueID should be the name of the queue in the
// cloud tasks console.
func newGCP(cfg *config.Config, client *cloudtasks.Client, queueID string) (_ *GCP, err error) {
	defer derrors.Wrap(&err, "newGCP(cfg, client, %q)", queueID)
	if queueID == "" {
		return nil, errors.New("empty queueID")
	}
	if cfg.ProjectID == "" {
		return nil, errors.New("empty ProjectID")
	}
	if cfg.LocationID == "" {
		return nil, errors.New("empty LocationID")
	}
	if cfg.QueueURL == "" {
		return nil, errors.New("empty QueueURL")
	}
	if cfg.ServiceAccount == "" {
		return nil, errors.New("empty ServiceAccount")
	}
	return &GCP{
		client:    client,
		queueName: fmt.Sprintf("projects/%s/locations/%s/queues/%s", cfg.ProjectID, cfg.LocationID, queueID),
		queueURL:  cfg.QueueURL,
		token: &taskspb.HttpRequest_OidcToken{
			OidcToken: &taskspb.OidcToken{
				ServiceAccountEmail: cfg.ServiceAccount,
			},
		},
	}, nil
}

// Enqueue enqueues a task on GCP.
// It returns an error if there was an error hashing the task name, or
// an error pushing the task to GCP.
// If the task was a duplicate, it returns (false, nil).
func (q *GCP) EnqueueScan(ctx context.Context, task Task, opts *Options) (enqueued bool, err error) {
	defer derrors.WrapStack(&err, "queue.EnqueueScan(%s, %s, %v)", task.Path(), task.Params(), opts)
	if opts == nil {
		opts = &Options{}
	}
	// Cloud Tasks enforces an RPC timeout of at most 30s. I couldn't find this
	// in the documentation, but using a larger value, or no timeout, results in
	// an InvalidArgument error with the text "The deadline cannot be more than
	// 30s in the future."
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	req, err := q.newTaskRequest(task, opts)
	if err != nil {
		return false, fmt.Errorf("newTaskRequest: %v", err)
	}

	enqueued = true
	if _, err := q.client.CreateTask(ctx, req); err != nil {
		if status.Code(err) == codes.AlreadyExists {
			log.Debugf(ctx, "ignoring duplicate task ID %s", req.Task.Name)
			enqueued = false
		} else {
			return false, fmt.Errorf("q.client.CreateTask(ctx, req): %v", err)
		}
	}
	return enqueued, nil
}

// Options is used to provide option arguments for a task queue.
type Options struct {
	// Namespace prefixes the URL path.
	Namespace string
	// DisableProxyFetch reports whether proxyfetch should be set to off when
	// making a fetch request.
	DisableProxyFetch bool

	// TaskNameSuffix is appended to the task name to force reprocessing of
	// tasks that would normally be de-duplicated.
	TaskNameSuffix string
}

// Maximum timeout for HTTP tasks.
// See https://cloud.google.com/tasks/docs/creating-http-target-tasks.
const maxCloudTasksTimeout = 30 * time.Minute

const disableProxyFetchParam = "proxyfetch=off"

func (q *GCP) newTaskRequest(task Task, opts *Options) (*taskspb.CreateTaskRequest, error) {
	if opts.Namespace == "" {
		return nil, errors.New("Options.Namespace cannot be empty")
	}
	relativeURI := fmt.Sprintf("/%s/scan/%s", opts.Namespace, task.Path())
	params := task.Params()
	if opts.DisableProxyFetch {
		if params == "" {
			params = disableProxyFetchParam
		} else {
			params += "&" + disableProxyFetchParam
		}
	}
	if params != "" {
		relativeURI += "?" + params
	}

	taskID := newTaskID(opts.Namespace, task)
	taskpb := &taskspb.Task{
		Name:             fmt.Sprintf("%s/tasks/%s", q.queueName, taskID),
		DispatchDeadline: durationpb.New(maxCloudTasksTimeout),
		MessageType: &taskspb.Task_HttpRequest{
			HttpRequest: &taskspb.HttpRequest{
				HttpMethod:          taskspb.HttpMethod_POST,
				Url:                 q.queueURL + relativeURI,
				AuthorizationHeader: q.token,
			},
		},
	}
	req := &taskspb.CreateTaskRequest{
		Parent: q.queueName,
		Task:   taskpb,
	}
	// If suffix is non-empty, append it to the task name.
	// This lets us force reprocessing of tasks that would normally be de-duplicated.
	if opts.TaskNameSuffix != "" {
		req.Task.Name += "-" + opts.TaskNameSuffix
	}
	return req, nil
}

// Create a task ID for the given task.
// Tasks with the same ID that are created within a few hours of each other. will be de-duplicated.
// See https://cloud.google.com/tasks/docs/reference/rpc/google.cloud.tasks.v2#createtaskrequest
// under "Task De-duplication".
func newTaskID(namespace string, task Task) string {
	name := task.Name()
	// Hash the path and params of the task.
	hasher := sha256.New()
	io.WriteString(hasher, task.Path())
	io.WriteString(hasher, task.Params())
	hash := hex.EncodeToString(hasher.Sum(nil))
	return escapeTaskID(fmt.Sprintf("%s-%s-%s", name, namespace, hash[:8]))
}

// escapeTaskIDs escapes s so it contains only valid characters for a Cloud Tasks name.
// It tries to produce a readable result.
// Task IDs can contain only letters ([A-Za-z]), numbers ([0-9]), hyphens (-), or underscores (_).
func escapeTaskID(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-':
			b.WriteRune(r)
		case r == '_':
			b.WriteString("__")
		case r == '/':
			b.WriteString("_-")
		case r == '@':
			b.WriteString("_")
		case r == '.':
			b.WriteString("_")
		default:
			fmt.Fprintf(&b, "_%04x", r)
		}
	}
	return b.String()
}

// InMemory is a Queue implementation that schedules in-process fetch
// operations. Unlike the GCP task queue, it will not automatically retry tasks
// on failure.
//
// This should only be used for local development.
type InMemory struct {
	queue chan Task
	done  chan struct{}
}

type inMemoryProcessFunc func(context.Context, Task) (int, error)

// NewInMemory creates a new InMemory that asynchronously fetches
// from proxyClient and stores in db. It uses workerCount parallelism to
// execute these fetches.
func NewInMemory(ctx context.Context, workerCount int, processFunc inMemoryProcessFunc) *InMemory {
	q := &InMemory{
		queue: make(chan Task, 1000),
		done:  make(chan struct{}),
	}
	sem := make(chan struct{}, workerCount)
	go func() {
		for v := range q.queue {
			select {
			case <-ctx.Done():
				return
			case sem <- struct{}{}:
			}

			// If a worker is available, make a request to the fetch service inside a
			// goroutine and wait for it to finish.
			go func(t Task) {
				defer func() { <-sem }()

				log.Infof(ctx, "Fetch requested: %v (workerCount = %d)", t, cap(sem))

				fetchCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
				defer cancel()

				if _, err := processFunc(fetchCtx, t); err != nil {
					log.Errorf(fetchCtx, err, "processFunc(%v)", t)
				}
			}(v)
		}
		for i := 0; i < cap(sem); i++ {
			select {
			case <-ctx.Done():
				panic(fmt.Sprintf("InMemory queue context done: %v", ctx.Err()))
			case sem <- struct{}{}:
			}
		}
		close(q.done)
	}()
	return q
}

// Enqueue pushes a fetch task into the local queue to be processed
// asynchronously.
func (q *InMemory) EnqueueScan(ctx context.Context, task Task, _ *Options) (bool, error) {
	q.queue <- task
	return true, nil
}

// WaitForTesting waits for all queued requests to finish. It should only be
// used by test code.
func (q *InMemory) WaitForTesting(ctx context.Context) {
	close(q.queue)
	<-q.done
}
