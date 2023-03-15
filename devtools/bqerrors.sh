#!/bin/bash

# Copyright 2023 The Go Authors. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

# List counts of errors by date in BigQuery tables.

set -e

source devtools/lib.sh || { echo "Are you at repo root?"; exit 1; }

usage() {
  die "usage: $0 DATASET"
}

bq_error_query() {
  local -r table=$1
  local q="
        select date(created_at) as date, error_category, count(*) as count
        from $table
        group by 1, 2
        order by 1 desc"
  bq query $q
}

main() {
  local dataset=$1
  if [[ $dataset == '' ]]; then
    usage
  fi
  local -r project=$(tfvar prod_project)
  if [[ $project = '' ]]; then
    die "missing TF_VAR_prod_project"
  fi

  bq_error_query $project.$dataset.govulncheck
}


main "$@"
