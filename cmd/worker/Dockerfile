# Copyright 2023 The Go Authors. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

# This Dockerfile expects the build context to be the repo root.

# To test that the worker built with this Dockerfile runs, run
#   make test
# from the repo root.

# NOTE: don't put anything in /tmp here. It will work locally,
# but Cloud Run mounts something else to /tmp, so anything
# installed here will be shadowed.


FROM golang:1.20.2

LABEL maintainer="Go Ecosystem Team <go-ecosystem-team@google.com>"

#### Preliminaries

WORKDIR /

# Create some directories.

# The worker binary and related files live here.
RUN mkdir /app

# When debugging the sandbox manually, run this as well:
# RUN mkdir /tmp/modules

# Where binaries live.
# Mapped by the sandbox config to the same place inside the sandbox.
# If you change this, you must also edit the bind mount in config.json.commented.
#
# We use an ARG command here to make a variable, but this is not intended to be
# provided as a command-line argument to `docker build`.
ARG BINARY_DIR=/app/binaries

RUN mkdir $BINARY_DIR

#### Sandbox setup

# Install runsc.
ADD https://storage.googleapis.com/gvisor/releases/release/20230320.0/x86_64/runsc /usr/local/bin/
RUN chmod a+rx /usr/local/bin/runsc

# Set up for runsc.
# runsc expects a directory called a "bundle" that contains a config.json
# file and an OS filesystem.

# Create the runsc bundle.
WORKDIR /bundle

# The root of the bundle filesystem.
RUN mkdir rootfs

# go-image.tar.gz is a complete Docker image of a Go installation in tar format.
# Use it for the bundle's OS filesystem.
COPY go-image.tar.gz .
RUN tar --same-owner -pxzf go-image.tar.gz -C rootfs

# Copy the downloaded copy of the vuln DB
# into the /app dir similar to binaries.
ARG VULNDB_DIR=/app/go-vulndb
COPY go-vulndb $VULNDB_DIR

COPY config.json .

#### Building binaries

# Set the working directory outside $GOPATH to ensure module mode is enabled.
WORKDIR /src

# Copy go.mods and go.sums into the container.
# If they don't change, which is the common case, then docker can
# cache these COPYs and the subsequent RUN.
COPY go.mod go.sum checks.bash ./

# Copy the repo from local machine into Docker client’s current working
# directory, so that we can use it to build the binary.
# See .dockerignore at the repo root for excluded files.
COPY . /src

# Download the dependencies.
RUN go mod download

# Build the worker binary and put it in /app.
RUN go build -mod=readonly -o /app/worker ./cmd/worker

# TODO: install the latest version of govulncheck?
# Build the version of govulncheck specified in the go.mod file.
RUN go build -o $BINARY_DIR golang.org/x/vuln/cmd/govulncheck

# Build the program that runs govulncheck inside the sandbox.
RUN go build -mod=readonly -o $BINARY_DIR/govulncheck_sandbox ./cmd/govulncheck_sandbox

# Build the program that runs govulncheck comparisons inside the sandbox
RUN go build -mod=readonly -o $BINARY_DIR/govulncheck_compare ./cmd/govulncheck_compare

# Build the sandbox runner program and put it in the bundle root.
RUN go build -mod=readonly -o /bundle/rootfs/runner ./internal/sandbox/runner.go


#### Worker setup

WORKDIR /app

ARG DOCKER_IMAGE
ENV DOCKER_IMAGE=$DOCKER_IMAGE

ARG BQ_DATASET
ENV GO_ECOSYSTEM_BIGQUERY_DATASET=$BQ_DATASET

ENV GO_ECOSYSTEM_BINARY_DIR=$BINARY_DIR

ENV GO_ECOSYSTEM_VULNDB_DIR=$VULNDB_DIR

CMD ["./worker"]
