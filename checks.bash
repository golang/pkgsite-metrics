#!/usr/bin/env bash
# Copyright 2023 The Go Authors. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

# Not run by unit tests. Intended to help authors
# during development.

go version

# Ensure that installed go binaries are on the path.
# This bash expression follows the algorithm described at the top of
# `go install help`: first try $GOBIN, then $GOPATH/bin, then $HOME/go/bin.
go_install_dir=${GOBIN:-${GOPATH:-$HOME/go}/bin}
PATH=$PATH:$go_install_dir

source devtools/lib.sh

# ensure_go_binary verifies that a binary exists in $PATH corresponding to the
# given go-gettable URI. If no such binary exists, it is fetched via `go get`.
ensure_go_binary() {
  local binary=$(basename $1)
  if ! [ -x "$(command -v $binary)" ]; then
    info "Installing: $1"
    # Install the binary in a way that doesn't affect our go.mod file.
    go install $1
  fi
}

# check_vet runs go vet on source files.
check_vet() {
  runcmd go vet -all ./...
}

# check_staticcheck runs staticcheck on source files.
check_staticcheck() {
    ensure_go_binary honnef.co/go/tools/cmd/staticcheck
    runcmd staticcheck ./...
}

# check_misspell runs misspell on source files.
check_misspell() {
  ensure_go_binary github.com/client9/misspell/cmd/misspell
  runcmd misspell -error $(find . -name .git -prune \
    -o -name .terraform -prune \
    -o -type f -not -name modules.txt -not -name '*.svg' -not -name '*.ts.snap' -not -name '*.json')
}

# check_integration prints a warning if the environment
# variable for integration testing is not set.
check_integration() {
  if [[ "${GO_ECOSYSTEM_INTEGRATION_TESTING}" != "1" ]]; then
    warn "Running go test ./... will skip integration tests (GO_ECOSYSTEM_INTEGRATION_TESTING != 1)"
  fi
}

go_linters() {
  check_vet
  check_staticcheck
  check_misspell
}

go_modtidy() {
  runcmd go mod tidy
}

runchecks() {
  check_integration
  go_linters
  go_modtidy
}

usage() {
  cat <<EOUSAGE
Usage: $0 [subcommand]
Available subcommands:
  help           - display this help message
EOUSAGE
}

main() {
  case "$1" in
    "-h" | "--help" | "help")
      usage
      exit 0
      ;;
    "")
      runchecks
      ;;
    *)
      usage
      exit 1
  esac
  if [[ $EXIT_CODE != 0 ]]; then
    err "FAILED; see errors above"
  fi
  exit $EXIT_CODE
}

main $@
