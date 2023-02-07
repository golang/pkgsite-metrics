# Copyright 2022 The Go Authors. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

# Library of useful bash functions and variables.

RED=; GREEN=; YELLOW=; NORMAL=;
MAXWIDTH=0

if tput setaf 1 >& /dev/null; then
  RED=`tput setaf 1`
  GREEN=`tput setaf 2`
  YELLOW=`tput setaf 3`
  NORMAL=`tput sgr0`
  MAXWIDTH=$(( $(tput cols) - 2 ))
fi

EXIT_CODE=0

info() { echo -e "${GREEN}$@${NORMAL}" 1>&2; }
warn() { echo -e "${YELLOW}$@${NORMAL}" 1>&2; }
err() { echo -e "${RED}$@${NORMAL}" 1>&2; EXIT_CODE=1; }

die() {
  err $@
  exit 1
}

dryrun=false

# runcmd prints an info log describing the command that is about to be run, and
# then runs it. It sets EXIT_CODE to non-zero if the command fails, but does not exit
# the script.
runcmd() {
  msg="$@"
  if $dryrun; then
    echo -e "${YELLOW}dryrun${GREEN}\$ $msg${NORMAL}"
    return 0
  fi
  # Truncate command logging for narrow terminals.
  # Account for the 2 characters of '$ '.
  if [[ $MAXWIDTH -gt 0 && ${#msg} -gt $MAXWIDTH ]]; then
    msg="${msg::$(( MAXWIDTH - 3 ))}..."
  fi

  echo -e "$@\n" 1>&2;
  $@ || err "command failed"
}

# tfvar NAME returns the value of the terraform variable NAME.
tfvar() {
  local v=TF_VAR_$1
  echo ${!v}
}

worker_url() {
  local env=$1
  echo https://${env}-${GO_ECOSYSTEM_WORKER_URL_SUFFIX}
}

impersonation_service_account() {
  local env=$1
  case $env in
    prod|dev) echo impersonate@$(tfvar ${env}_project).iam.gserviceaccount.com;;
    *) die "usage: $0 (dev | prod)";;
  esac
}

impersonation_token() {
  local env=$1
  gcloud --impersonate-service-account $(impersonation_service_account $env) \
    auth print-identity-token \
    --include-email
}
