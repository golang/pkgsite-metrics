#!/bin/bash

# Copyright 2022 The Go Authors. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

# Deploy the go-ecosystem worker to Cloud Run, using Cloud Build.

set -e

source devtools/lib.sh || { echo "Are you at repo root?"; exit 1; }

usage() {
  die "usage: $0 [-n] (dev | prod) BIGQUERY_DATASET"
}

# Report whether the current repo's workspace has no uncommitted files.
clean_workspace() {
  [[ $(git status --porcelain) == '' ]]
}

main() {
  local prefix=
  if [[ $1 = '-n' ]]; then
    prefix='echo dryrun: '
    shift
  fi

  local env=$1

  case $env in
    dev|prod);;
    *) usage;;
  esac

  local dataset=$2
  if [[ $dataset = '' ]]; then
    usage
  fi

  if which grants > /dev/null; then
    local allowed=false
    while read g _ ok _; do
      if [[ $ok = OK ]]; then
        allowed=true
      fi
    done < <(grants check $GO_ECOSYSTEM_DEPLOY_GROUPS)
    if ! $allowed; then
      die "You need a grant for one of: $GO_ECOSYSTEM_DEPLOY_GROUPS"
    fi
  fi

  local project=$(tfvar ${env}_project)
  if [[ $project = '' ]]; then
    die "no ${env}_project in terraform.tfvars"
  fi
  local commit=$(git rev-parse --short HEAD)
  local unclean
  if ! clean_workspace; then
    unclean="-unclean"
  fi

  $prefix gcloud builds submit \
    --project $project \
    --config deploy/worker.yaml \
    --substitutions SHORT_SHA=${commit}${unclean},_ENV=$env,_BQ_DATASET=$dataset
}

main $@
