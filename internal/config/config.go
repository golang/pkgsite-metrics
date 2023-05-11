// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package config resolves shared configuration for services, and
// provides functions to access this configuration.
package config

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/google/safehtml/template"
	"golang.org/x/net/context/ctxhttp"
	"golang.org/x/pkgsite-metrics/internal/derrors"
	mrpb "google.golang.org/genproto/googleapis/api/monitoredres"
)

// Config holds configuration information for the worker server.
type Config struct {
	// ProjectID is the Google Cloud ProjectID where the resources live.
	ProjectID string

	// VersionID is the identifier for the version currently running.
	// We do not use the version ID from Cloud Run (see
	// https://cloud.google.com/run/docs/reference/container-contract).
	// Instead, we use the DOCKER_IMAGE environment variable, set
	// in the Cloud Build deploy file.
	VersionID string

	// LocationID is the location for the GCP project.
	LocationID string

	// ServiceID names the Cloud Run service.
	ServiceID string

	// StaticPath is the directory containing static files.
	StaticPath template.TrustedSource

	// ServiceAccount is the email of the service account that this process
	// is running as when on GCP.
	ServiceAccount string

	// UseErrorReporting determines whether errors go to the Error Reporting API.
	UseErrorReporting bool

	// BigQueryDataset is the BigQuery dataset to write results to.
	BigQueryDataset string

	// QueueName is the name of the Cloud Tasks queue.
	QueueName string

	// QueueURL is the URL that the Cloud Tasks queue should send requests to.
	// It should be used when the worker is not on AppEngine.
	QueueURL string

	// LocalQueueWorkers is the number of concurrent requests to the fetch service,
	// when running locally.
	LocalQueueWorkers int

	// MonitoredResource represents the resource that is running the current binary.
	// It might be a Google AppEngine app, a Cloud Run service, or a Kubernetes pod.
	// See https://cloud.google.com/monitoring/api/resources for more details:
	// "An object representing a resource that can be used for monitoring, logging,
	// billing, or other purposes. Examples include virtual machine instances,
	// databases, and storage devices such as disks.""
	MonitoredResource *mrpb.MonitoredResource

	// DevMode indicates whether the server is running in development mode.
	DevMode bool

	// VulnDBBucketProjectID is the project ID for the vuln DB bucket and its
	// associated load balancer.
	VulnDBBucketProjectID string

	// BinaryBucket holds binaries for govulncheck scanning.
	BinaryBucket string

	// BinaryDir is the local directory for binaries.
	BinaryDir string

	// VulnDBDir is the local directory of the vulnerability database.
	VulnDBDir string

	// PkgsiteDBHost is the host of the pkgsite db used to find modules to scan.
	PkgsiteDBHost string
	// PkgsiteDBPort is the port of the pkgsite db used to find modules to scan.
	PkgsiteDBPort string
	// PkgsiteDBName is the name of the pkgsite db used to find modules to scan.
	PkgsiteDBName string
	// PkgsiteDBUser is the user of the pkgsite db used to find modules to scan.
	PkgsiteDBUser string
	// PkgsiteDBSecret is the name of the secret holding the pkgsite db password.
	PkgsiteDBSecret string

	// Insecure runs analysis binaries without sandbox.
	Insecure bool

	// ProxyURL is the url for the Go module proxy.
	ProxyURL string
}

// Init resolves all configuration values provided by the config package. It
// must be called before any configuration values are used.
func Init(ctx context.Context) (_ *Config, err error) {
	defer derrors.Wrap(&err, "config.Init(ctx)")
	// Build a Config from the execution environment, loading some values
	// from environment variables.

	var ts template.TrustedSource
	if f := flag.Lookup("static"); f != nil {
		ts = template.TrustedSourceFromFlag(f.Value)
	}
	cfg := &Config{
		ProjectID:             os.Getenv("GOOGLE_CLOUD_PROJECT"),
		ServiceID:             os.Getenv("GO_ECOSYSTEM_SERVICE_ID"),
		VersionID:             os.Getenv("DOCKER_IMAGE"),
		LocationID:            "us-central1",
		StaticPath:            ts,
		BigQueryDataset:       GetEnv("GO_ECOSYSTEM_BIGQUERY_DATASET", "disable"),
		QueueName:             os.Getenv("GO_ECOSYSTEM_QUEUE_NAME"),
		QueueURL:              os.Getenv("GO_ECOSYSTEM_QUEUE_URL"),
		VulnDBBucketProjectID: os.Getenv("GO_ECOSYSTEM_VULNDB_BUCKET_PROJECT"),
		BinaryBucket:          os.Getenv("GO_ECOSYSTEM_BINARY_BUCKET"),
		BinaryDir:             GetEnv("GO_ECOSYSTEM_BINARY_DIR", "/tmp/binaries"),
		VulnDBDir:             GetEnv("GO_ECOSYSTEM_VULNDB_DIR", "/tmp/go-vulndb"),
		PkgsiteDBHost:         GetEnv("GO_ECOSYSTEM_PKGSITE_DB_HOST", "localhost"),
		PkgsiteDBPort:         GetEnv("GO_ECOSYSTEM_PKGSITE_DB_PORT", "5432"),
		PkgsiteDBName:         GetEnv("GO_ECOSYSTEM_PKGSITE_DB_NAME", "discovery-db"),
		PkgsiteDBUser:         GetEnv("GO_ECOSYSTEM_PKGSITE_DB_USER", "postgres"),
		PkgsiteDBSecret:       os.Getenv("GO_ECOSYSTEM_PKGSITE_DB_SECRET"),
		ProxyURL:              GetEnv("GO_MODULE_PROXY_URL", "https://proxy.golang.org"),
	}
	if OnCloudRun() {
		sa, err := gceMetadata(ctx, "instance/service-accounts/default/email")
		if err != nil {
			return nil, err
		}
		cfg.ServiceAccount = sa
		configName := os.Getenv("K_CONFIGURATION")
		cfg.MonitoredResource = &mrpb.MonitoredResource{
			Type: "cloud_run_revision",
			Labels: map[string]string{
				"project_id":         cfg.ProjectID,
				"service_name":       cfg.ServiceID,
				"revision_name":      cfg.VersionID,
				"configuration_name": configName,
			},
		}
		// Only enable error reporting for prod. The configName is the
		// Cloud Run service name: "dev-ecosystem-worker" or "prod-ecosystem-worker".
		cfg.UseErrorReporting = strings.HasPrefix(configName, "prod-")
	} else { // running locally, perhaps
		cfg.MonitoredResource = &mrpb.MonitoredResource{
			Type:   "global",
			Labels: map[string]string{"project_id": cfg.ProjectID},
		}
	}
	return cfg, nil
}

// OnCloudRun reports whether the current process is running on Cloud Run.
func OnCloudRun() bool {
	// Use the presence of the environment variables provided by Cloud Run.
	// See https://cloud.google.com/run/docs/reference/container-contract.
	for _, ev := range []string{"K_SERVICE", "K_REVISION", "K_CONFIGURATION"} {
		if os.Getenv(ev) == "" {
			return false
		}
	}
	return true
}

func (c *Config) Validate() error {
	if c.ProjectID == "" {
		return errors.New("missing project")
	}
	if c.BigQueryDataset == "" {
		return errors.New("missing dataset")
	}
	return nil
}

// Dump outputs the current config information to the given Writer.
func (c *Config) Dump(w io.Writer) error {
	fmt.Fprint(w, "config: ")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "    ")
	return enc.Encode(c)
}

// GetEnv looks up the given key from the environment, returning its value if
// it exists, and otherwise returning the given fallback value.
func GetEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

// GetEnvInt performs GetEnv(key, fallback) and parses the
// result as int. If parsing fails, returns errVal.
func GetEnvInt(key, fallback string, errVal int) int {
	v := GetEnv(key, fallback)
	i, err := strconv.Atoi(v)
	if err != nil {
		return errVal
	}
	return i
}

// gceMetadata reads a metadata value from GCE.
// For the possible values of name, see
// https://cloud.google.com/appengine/docs/standard/java/accessing-instance-metadata.
func gceMetadata(ctx context.Context, name string) (_ string, err error) {
	// See https://cloud.google.com/appengine/docs/standard/java/accessing-instance-metadata.
	// (This documentation doesn't exist for Golang, but it seems to work).
	defer derrors.Wrap(&err, "gceMetadata(ctx, %q)", name)

	const metadataURL = "http://metadata.google.internal/computeMetadata/v1/"
	req, err := http.NewRequest("GET", metadataURL+name, nil)
	if err != nil {
		return "", fmt.Errorf("http.NewRequest: %v", err)
	}
	req.Header.Set("Metadata-Flavor", "Google")
	resp, err := ctxhttp.Do(ctx, nil, req)
	if err != nil {
		return "", fmt.Errorf("ctxhttp.Do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("bad status: %s", resp.Status)
	}
	bytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("io.ReadAll: %v", err)
	}
	return string(bytes), nil
}
