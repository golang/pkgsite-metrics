# Copyright 2021 The Go Authors. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

# Config for metrics worker.

################################################################
# Inputs.

variable "env" {
  description = "environment name"
  type        = string
}

variable "project" {
  description = "GCP project"
  type        = string
}

variable "region" {
  description = "GCP region"
  type        = string
}

variable "pkgsite_db_project" {
  description = "pkgsite project"
  type        = string
}

variable "pkgsite_db_name" {
  description = "pkgsite DB name"
  type        = string
}

variable "use_profiler" {
  description = "use Stackdriver Profiler"
  type        = bool
}

locals {
  worker_url             = data.google_cloud_run_service.worker.status[0].url
  tz                     = "America/New_York"
  worker_service_account = "worker@${var.project}.iam.gserviceaccount.com"
  pkgsite_db             = "${var.pkgsite_db_project}:${var.region}:${var.pkgsite_db_name}"
}


################################################################
# Cloud Run service.

locals {
  concurrency         = 1
  container_mem_limit = 32                                     # container memory limit in gigabytes
  go_mem_limit        = floor(local.container_mem_limit * 0.9) # allow 10% for other users of memory
}

resource "google_cloud_run_service" "worker" {
  provider = google-beta

  lifecycle {
    ignore_changes = [
      # When we deploy, we may use different clients at different versions.
      # Ignore those changes, and others.
      metadata[0].annotations["run.googleapis.com/client-name"],
      metadata[0].annotations["run.googleapis.com/client-version"],
      metadata[0].annotations["run.googleapis.com/ingress"],
      metadata[0].annotations["run.googleapis.com/operation-id"],
      metadata[0].annotations["client.knative.dev/user-image"],
      template[0].metadata[0].annotations["run.googleapis.com/client-name"],
      template[0].metadata[0].annotations["run.googleapis.com/client-version"],
      template[0].metadata[0].annotations["client.knative.dev/user-image"],
    ]
  }

  name     = "${var.env}-ecosystem-worker"
  project  = var.project
  location = var.region

  metadata {
    annotations = {
      "run.googleapis.com/launch-stage" = "BETA"
    }
  }

  template {
    spec {
      containers {
        # Get the image from GCP (see the "data" block below).
        # Exception: when first creating the service, replace this with a hardcoded
        # image tag.
        image = data.google_cloud_run_service.worker.template[0].spec[0].containers[0].image
        env {
          name  = "GOOGLE_CLOUD_PROJECT"
          value = var.project
        }
        env {
          name  = "GO_ECOSYSTEM_WORKER_USE_PROFILER"
          value = var.use_profiler
        }
        resources {
          limits = {
            "cpu"    = "8000m"
            "memory" = "${local.container_mem_limit}Gi"
          }
        }
        env {
          name  = "GO_ECOSYSTEM_QUEUE_URL"
          value = local.worker_url
        }
        env {
          name  = "GO_ECOSYSTEM_QUEUE_NAME"
          value = "${var.env}-worker-tasks"
        }
        env {
          name = "GITHUB_ACCESS_TOKEN"
          value_from {
            secret_key_ref {
              name = google_secret_manager_secret.github_access_token.secret_id
              key  = "latest"
            }
          }
        }
        env {
          name  = "CLOUD_RUN_CONCURRENCY"
          value = local.concurrency
        }
        # Set Go GC mem limit.
        # See https://pkg.go.dev/runtime#hdr-Environment_Variables.
        env {
          name  = "GOMEMLIMIT"
          value = "${local.go_mem_limit}GiB"
        }
        env {
          name  = "GO_ECOSYSTEM_PKGSITE_DB_HOST"
          value = "/cloudsql/${local.pkgsite_db}"
        }
        env {
          name  = "GO_ECOSYSTEM_PKGSITE_DB_PORT"
          value = "5432"
        }
        env {
          name  = "GO_ECOSYSTEM_PKGSITE_DB_NAME"
          value = var.pkgsite_db_name
        }
        env {
          name  = "GO_ECOSYSTEM_PKGSITE_DB_USER"
          value = "frontend"
        }
        env {
          name  = "GO_ECOSYSTEM_PKGSITE_DB_SECRET"
          value = "projects/${var.pkgsite_db_project}/secrets/frontend-database-password"
        }
      }

      service_account_name = local.worker_service_account

      # 60 minutes is the maximum Cloud Run request time.
      timeout_seconds = 60 * 60

      container_concurrency = local.concurrency
    }

    # Set min and max number of instances.
    metadata {
      annotations = {
        "autoscaling.knative.dev/minScale"         = "10"
        "autoscaling.knative.dev/maxScale"         = "500"
        "run.googleapis.com/cloudsql-instances"    = local.pkgsite_db
        "run.googleapis.com/execution-environment" = "gen2"
      }
    }
  }

  autogenerate_revision_name = true

  traffic {
    latest_revision = true
    percent         = 100
  }
}

# We deploy new images with gcloud, not terraform, so we need to
# make sure that "terraform apply" doesn't change the deployed image
# to whatever is in this file. (The image attribute is required in
# a Cloud Run config; it can't be empty.)
#
# We use this data source is used to determine the deployed image.
data "google_cloud_run_service" "worker" {
  name     = "${var.env}-ecosystem-worker"
  project  = var.project
  location = var.region
}

################################################################
# Other components.

resource "google_cloud_tasks_queue" "worker_tasks" {
  name     = "${var.env}-worker-tasks"
  location = var.region
  project  = var.project

  rate_limits {
    max_concurrent_dispatches = 20
    max_dispatches_per_second = 500
  }

  retry_config {
    max_attempts       = -1
    max_backoff        = "1440s"
    max_doublings      = 16
    max_retry_duration = "604800s"
    min_backoff        = "60s"
  }

  stackdriver_logging_config {
    sampling_ratio = 1
  }
}

resource "google_secret_manager_secret" "github_access_token" {
  secret_id = "${var.env}-github-access-token"
  project   = var.project
  replication {
    automatic = true
  }
}

resource "google_cloud_scheduler_job" "requests" {
  count       = var.env == "prod" ? 1 : 0
  name        = "${var.env}-requests"
  description = "Get count of vuln DB requests."
  schedule    = "0 7 * * *" # 7 AM daily
  time_zone   = local.tz
  project     = var.project

  http_target {
    http_method = "GET"
    uri         = "${local.worker_url}/requests"
    oidc_token {
      service_account_email = local.worker_service_account
      audience              = local.worker_url
    }
  }
}


resource "google_cloud_scheduler_job" "enqueueall" {
  count       = var.env == "prod" ? 1 : 0
  name        = "${var.env}-enqueueall"
  description = "Enqueue modules for all modes."
  schedule    = "0 8 * * *" # 8 AM daily
  time_zone   = local.tz
  project     = var.project

  http_target {
    http_method = "GET"
    uri         = "${local.worker_url}/vulncheck/enqueueall?min=15"
    oidc_token {
      service_account_email = local.worker_service_account
      audience              = local.worker_url
    }
  }
}

resource "google_cloud_scheduler_job" "results" {
  count       = var.env == "prod" ? 1 : 0
  name        = "${var.env}-insert-results"
  description = "Insert results into report table."
  schedule    = "0 20 * * *" # 8 PM daily
  time_zone   = local.tz
  project     = var.project

  http_target {
    http_method = "GET"
    uri         = "${local.worker_url}/vulncheck/insert-results"
    oidc_token {
      service_account_email = local.worker_service_account
      audience              = local.worker_url
    }
  }
}
