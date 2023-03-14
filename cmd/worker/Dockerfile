# Copyright 2023 The Go Authors. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

# This Dockerfile expects the build context to be the repo root.

# To test that the worker built with this Dockerfile runs, run
#   make test
# from the repo root.

FROM golang:1.19.4

LABEL maintainer="Go Ecosystem Team <go-ecosystem-team@google.com>"

#### Preliminaries

WORKDIR /

# Create some directories.

# The worker binary and related files live here.
RUN mkdir app
# The module being analyzed is unzipped here.
# The sandbox mounts this directory.
RUN mkdir module

# Where binaries and modules live.
# The sandbox config.json file maps these to the same paths
# inside the sandbox.
RUN mkdir /tmp/binaries
RUN mkdir /tmp/modules


#### Sandbox setup

# Install runsc.
ADD https://storage.googleapis.com/gvisor/releases/release/20221107.0/x86_64/runsc /usr/local/bin/
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

# Copy the downloaded copy of the vuln DB into the bundle root.
COPY go-vulndb rootfs/go-vulndb

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

# Install the latest version of govulncheck in the binaries directory.
RUN GOBIN=/tmp/binaries go install golang.org/x/vuln/cmd/govulncheck@latest

# Build the program that runs govulncheck inside the sandbox and install it in the sandbox's
# binaries directory.
RUN go build -mod=readonly -o /tmp/binaries/govulncheck_sandbox ./cmd/govulncheck_sandbox

# Build the sandbox runner program and put it in the bundle root.
RUN go build -mod=readonly -o /bundle/rootfs/runner ./internal/sandbox/runner.go


#### Worker setup

WORKDIR /app

ARG DOCKER_IMAGE
ENV DOCKER_IMAGE=$DOCKER_IMAGE

ARG BQ_DATASET
ENV GO_ECOSYSTEM_BIGQUERY_DATASET=$BQ_DATASET

CMD ["./worker"]
