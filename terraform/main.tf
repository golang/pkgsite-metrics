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
      version = "~> 3.90.1"
      source  = "hashicorp/google"
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

# Enabled APIs

resource "google_project_service" "apis" {
  for_each = toset([
    "bigquery",
    "cloudbuild",
    "cloudscheduler",
    "cloudtasks",
    "cloudtrace",
    "compute",
    "containerregistry",
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
    # Let anyone in the ecosystem group get an access token for this service account.
    role    = "roles/iam.serviceAccountTokenCreator"
    members = [var.team_group]
  }
  binding {
    # Let anyone in the ecosystem group act as this service account.
    role    = "roles/iam.serviceAccountUser"
    members = [var.team_group]
  }
}



# Deployment environments

module "prod" {
  source             = "./environment"
  env                = "prod"
  project            = var.prod_project
  region             = local.region
  pkgsite_db_project = var.pkgsite_db_project
  pkgsite_db_name    = var.pkgsite_db_name
  use_profiler       = true
}


module "dev" {
  source             = "./environment"
  env                = "dev"
  project            = var.dev_project
  region             = local.region
  pkgsite_db_project = var.pkgsite_db_project
  pkgsite_db_name    = var.pkgsite_db_name
  use_profiler       = false
}

