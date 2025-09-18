# Copyright 2021 The Go Authors. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

# Terraform configuration for GCP components from this repo.

terraform {
  required_version = ">= 1.0.9, < 2.0.0"
  # Store terraform state in a GCS bucket, so all team members share it.
  backend "gcs" {
    bucket = "go-ecosystem"
  }
  required_providers {
    google = {
      version = "> 4.55.0"
      source  = "hashicorp/google-beta"
    }
  }
}

locals {
  region = "us-central1"
}

provider "google" {
  region = local.region
}

# Inputs for values that should not appear in the repo.
# Terraform will prompt for these when you run it, or
# you can put them in a local file that is only readable
# by you, and pass them to terraform.
# See https://www.terraform.io/docs/language/values/variables.html#variable-definitions-tfvars-files.


variable "prod_project" {
  description = "GCP project where resources live"
  type        = string
}

variable "dev_project" {
  description = "GCP project where resources live"
  type        = string
}

variable "team_group" {
  description = "GCP group for the entire team"
  type        = string
}

variable "deployers_group" {
  description = "GCP group for deployers"
  type        = string
}

variable "pkgsite_db_project" {
  description = "project containing pkgsite DB"
  type        = string
}

variable "pkgsite_db_name" {
  description = "name of pkgsite DB"
  type        = string
}

variable "vulndb_bucket_project" {
  description = "project ID for vuln DB bucket logs"
  type        = string
}

# Enabled APIs

resource "google_project_service" "apis" {
  for_each = toset([
    "bigquery",
    "cloudbuild",
    "clouderrorreporting",
    "cloudscheduler",
    "cloudtasks",
    "cloudtrace",
    "compute",
    "containerregistry",
    "firestore",
    "iap",
    "logging",
    "monitoring",
    "oslogin",
    "pubsub",
    "run",
    "secretmanager",
    "sql-component",
    "sqladmin",
    "storage-api",
    "storage-component"
  ])
  service            = "${each.key}.googleapis.com"
  disable_on_destroy = false
}

# Service accounts

resource "google_service_account" "worker" {
  account_id   = "worker"
  display_name = "ecosystem metrics worker service account"
  description  = "Service account used by ecosystem metrics services."
}

resource "google_service_account_iam_policy" "worker" {
  service_account_id = google_service_account.worker.name
  policy_data        = data.google_iam_policy.worker.policy_data
}

# Permissions on the worker service account.
# These grant other identities (like users and groups) permissions
# to do things to/with the service account.
# In IAM terms, the service account is acting as a resource here, not an identity.
# The permissions *for* the service account (those that let the service account
# do things, that treat the service account as an identity) are not represented
# in terraform because they are on the project resource, which is managed
# by an iam_policy file internal to Google.

data "google_iam_policy" "worker" {
  binding {
    # Let any ecosystem deployer act as this service account.
    role    = "roles/iam.serviceAccountUser"
    members = [var.deployers_group]
  }
}


resource "google_service_account" "impersonate" {
  account_id   = "impersonate"
  display_name = "impersonate service account"
  description  = "Users can act as this service account."
}

resource "google_service_account_iam_policy" "impersonate" {
  service_account_id = google_service_account.impersonate.name
  policy_data        = data.google_iam_policy.impersonate.policy_data
}

# Permissions on the impersonate service account.
data "google_iam_policy" "impersonate" {
  binding {
    # Let anyone in the ecosystem and golang group get an access token for this service account.
    role    = "roles/iam.serviceAccountTokenCreator"
    members = [
    	var.team_group,
	"group:golang-eng-policy@twosync.google.com"
	]
  }
  binding {
    # Let anyone in the ecosystem and golang group act as this service account.
    role    = "roles/iam.serviceAccountUser"
    members = [
    	var.team_group,
	"group:golang-eng-policy@twosync.google.com"
	]
  }
  binding {
    # Let anyone in the ecosystem and golang group view most of Cloud resources, including permissions.
    role    = "roles/viewer"
    members = [
    	var.team_group,
	"group:golang-eng-policy@twosync.google.com"
	]
  }
}

resource "google_logging_metric" "scheduler_errors" {
  name        = "cloud-scheduler-errors"
  description = "Number of errors from Cloud Scheduler jobs"
  filter      = "resource.type=cloud_scheduler_job AND severity>=ERROR"
  metric_descriptor {
    metric_kind = "DELTA"
    unit        = "1"
    value_type  = "INT64"
  }
}

resource "google_logging_metric" "build_errors" {
  name        = "cloud-build-errors"
  description = "Errors from Cloud Build"
  filter      = "resource.type=build AND textPayload=ERROR"
  metric_descriptor {
    metric_kind = "DELTA"
    unit        = "1"
    value_type  = "INT64"
  }
}



resource "google_monitoring_notification_channel" "email" {
  display_name = "Go Ecosystem Team Alerts"
  type         = "email"
  labels = {
    email_address = "go-ecosystem-team+alerts@google.com"
  }
}

resource "google_monitoring_alert_policy" "scheduler_job_failing" {
  display_name = "Cloud Scheduler Job Failing"

  conditions {
    display_name = "Instance Count"

    condition_threshold {
      filter          = <<-EOT
        metric.type="logging.googleapis.com/user/cloud-scheduler-errors"
      EOT
      comparison      = "COMPARISON_GT"
      threshold_value = 1
      aggregations {
        alignment_period     = "600s"
        cross_series_reducer = "REDUCE_SUM"
        per_series_aligner   = "ALIGN_DELTA"
      }
      duration = "0s"
      trigger { count = 1 }
    }
  }

  combiner = "OR"

  notification_channels = [google_monitoring_notification_channel.email.name]

}

resource "google_monitoring_alert_policy" "build_job_failing" {
  display_name = "Cloud Build Job Failing"

  conditions {
    display_name = "Instance Count"

    condition_threshold {
      filter          = <<-EOT
        metric.type="logging.googleapis.com/user/cloud-build-errors"
      EOT
      comparison      = "COMPARISON_GT"
      threshold_value = 1
      aggregations {
        alignment_period     = "600s"
        cross_series_reducer = "REDUCE_SUM"
        per_series_aligner   = "ALIGN_DELTA"
      }
      duration = "0s"
      trigger { count = 1 }
    }
  }

  combiner = "OR"

  notification_channels = [google_monitoring_notification_channel.email.name]

}


# Cloud Build trigger to deploy the prod worker on every push to master.
resource "google_cloudbuild_trigger" "deploy_prod_worker" {
  name = "Deploy-Prod-Ecosystem-Worker"
  trigger_template {
    branch_name = "master"
    repo_name   = "pkgsite-metrics"
  }
  filename = "deploy/worker.yaml"

  substitutions = {
    "_ENV"        = "prod"
    "_BQ_DATASET" = "prod"
  }
}

# Secret for computing HMACs to obfuscate VulnDB request IPs.
resource "google_secret_manager_secret" "vulndb-hmac-key" {
  secret_id = "vulndb-hmac-key"
  replication {
    auto {}
  }
}

# Deployment environments

module "prod" {
  source                = "./environment"
  env                   = "prod"
  project               = var.prod_project
  regions                = ["us-central1", "us-east1"]
  pkgsite_db_project    = var.pkgsite_db_project
  pkgsite_db_name       = var.pkgsite_db_name
  vulndb_bucket_project = var.vulndb_bucket_project
  use_profiler          = true
}


module "dev" {
  source                = "./environment"
  env                   = "dev"
  project               = var.dev_project
  regions                = ["us-central1", "us-east1"]
  pkgsite_db_project    = var.pkgsite_db_project
  pkgsite_db_name       = var.pkgsite_db_name
  vulndb_bucket_project = var.vulndb_bucket_project
  use_profiler          = false
}
