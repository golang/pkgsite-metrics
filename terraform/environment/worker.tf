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

variable "regions" {
  description = "GCP region(s)"
  type        = set(string)
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

variable "vulndb_bucket_project" {
  description = "project ID for vuln DB bucket logs"
  type        = string
}

locals {
  worker_url             = data.google_cloud_run_service.worker[tolist(var.regions)[0]].status[0].url
  tz                     = "America/New_York"
  worker_service_account = "worker@${var.project}.iam.gserviceaccount.com"
  pkgsite_db             = "${var.pkgsite_db_project}:${tolist(var.regions)[0]}:${var.pkgsite_db_name}"
  task_queues = flatten([
    for region in var.regions : [
      for i in range(7) : {
        name = format("%s-%s-%05s", var.env, region, i)
        region = region
        url = data.google_cloud_run_service.worker[region].status[0].url
      }
    ]
  ])
  # Move task queues into a map to make them easier to use with for_each
  task_queues_map = {
    for q in local.task_queues :
      q.name => q
    }
}


################################################################
# Cloud Run service.

locals {
  concurrency         = 1
  container_mem_limit = 32                                     # container memory limit in gigabytes
  go_mem_limit        = floor(local.container_mem_limit * 0.9) # allow 10% for other users of memory
}

resource "google_cloud_run_service" "worker" {
  for_each = var.regions
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
  location = each.value

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
        image = data.google_cloud_run_service.worker[each.value].template[0].spec[0].containers[0].image
        env {
          name  = "GOOGLE_CLOUD_PROJECT"
          value = var.project
        }
        env {
          name  = "GO_ECOSYSTEM_WORKER_USE_PROFILER"
          value = var.use_profiler
        }
        env {
          name = "GO_ECOSYSTEM_QUEUE_NAMES"
          value = join(",", [for queue in google_cloud_tasks_queue.worker_queues : queue.name])
        }
        resources {
          limits = {
            "cpu"    = "8000m"
            "memory" = "${local.container_mem_limit}Gi"
          }
        }
        env {
          name  = "GO_ECOSYSTEM_QUEUE_URLS"
          #value = data.google_cloud_run_service.worker[each.value].status[0].url
          value = join(",", [for queue in local.task_queues_map : queue.url])
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
        env {
          name  = "GO_ECOSYSTEM_BINARY_BUCKET"
          value = "go-ecosystem"
        }
        env {
          name  = "GO_ECOSYSTEM_VULNDB_BUCKET_PROJECT"
          value = var.vulndb_bucket_project
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
        "autoscaling.knative.dev/maxScale"         = each.value == "us-central1" ? "3738" : "625"
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
  for_each = var.regions
  name     = "${var.env}-ecosystem-worker"
  project  = var.project
  location = each.value
}

################################################################
# Other components.

resource "google_cloud_tasks_queue" "worker_queues" {
  for_each = local.task_queues_map
  project  = var.project
  name     = each.value.name
  location = each.value.region

  rate_limits {
    max_dispatches_per_second = 500
    max_concurrent_dispatches = 5000
  }

  retry_config {
    max_attempts       = 100
    max_backoff        = "1440s"
    max_doublings      = 16
    max_retry_duration = "604800s"
    min_backoff        = "60s"
  }
}

resource "google_cloud_scheduler_job" "vulndb" {
  count       = var.env == "prod" ? 1 : 0
  name        = "${var.env}-vulndb"
  description = "Compute vuln DB stats."
  schedule    = "0 6 * * *" # 6 AM daily
  time_zone   = local.tz
  project     = var.project

  http_target {
    http_method = "GET"
    uri         = "${local.worker_url}/vulndb"
    oidc_token {
      service_account_email = local.worker_service_account
      audience              = local.worker_url
    }
  }
}

resource "google_cloud_scheduler_job" "compute_requests" {
  count       = var.env == "prod" ? 1 : 0
  name        = "${var.env}-compute-requests"
  description = "Compute vuln DB request counts."
  schedule    = "0 7 * * *" # 7 AM daily
  time_zone   = local.tz
  project     = var.project

  attempt_deadline = "1800s" # 30 min max deadline for HTTP target
  http_target {
    http_method = "GET"
    uri         = "${local.worker_url}/compute-requests"
    oidc_token {
      service_account_email = local.worker_service_account
      audience              = local.worker_url
    }
  }
}


resource "google_cloud_scheduler_job" "enqueueall" {
  count       = var.env == "prod" ? 1 : 0
  name        = "${var.env}-enqueueall"
  description = "Enqueue modules for all modes that should be run frequently."
  schedule    = "0 8 * * 1,3,5" # 8 AM every Mon, Wed, and Fri
  time_zone   = local.tz
  project     = var.project

  attempt_deadline = "1800s" # 30 min max deadline for HTTP target
  http_target {
    http_method = "GET"
    uri         = "${local.worker_url}/govulncheck/enqueueall?min=0"
    oidc_token {
      service_account_email = local.worker_service_account
      audience              = local.worker_url
    }
  }
}

resource "google_cloud_scheduler_job" "enqueuecompare" {
  count       = var.env == "prod" ? 1 : 0
  name        = "${var.env}-enqueuecompare"
  description = "Enqueue modules for compare mode."
  schedule    = "0 20 * * SAT" # 8PM every Saturday
  time_zone   = local.tz
  project     = var.project

  attempt_deadline = "1800s" # 30 min max deadline for HTTP target
  http_target {
    http_method = "GET"
    uri         = "${local.worker_url}/govulncheck/enqueue?mode=compare&min=0"
    oidc_token {
      service_account_email = local.worker_service_account
      audience              = local.worker_url
    }
  }
}

resource "google_cloud_scheduler_job" "gomodstat" {
  count       = var.env == "prod" ? 1 : 0
  name        = "${var.env}-gomodstat"
  description = "Run gomodstat every week."
  schedule    = "0 16 * * FRI" # 4PM every Friday
  time_zone   = local.tz
  project     = var.project

  attempt_deadline = "1800s" # 30 min max deadline for HTTP target
  http_target {
    http_method = "GET"
    uri         = "${local.worker_url}/analysis/enqueue?binary=golang-gomodstat&skipinit=true&min=0"
    oidc_token {
      service_account_email = local.worker_service_account
      audience              = local.worker_url
    }
  }
}
