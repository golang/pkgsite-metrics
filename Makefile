# Copyright 2023 The Go Authors. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

# Makefile for common tasks.

default:
	@echo "usage: make TARGET"

# Copy a gzipped tar of a Go docker image from a bucket.
# The file must live in the repo directory so that cmd/worker/Dockerfile
# can access it.
# We assume that the file exists in the bucket. It can be created with
#   docker export $(shell docker create golang:1.19.4) | gzip
go-image.tar.gz:
	gsutil cp gs://go-ecosystem/$@ $@

# Download the Go vulnerability DB to a local directory, so vulndb can access it
# from the sandbox, which has no network connectivity.
#
# Get the last-modified time of the index.json file, which is reported as the
# last-modified time of the DB, and save it to a local file. (The last-modified
# time of the local index.json is not what we want: it is the time that gsutil cp
# wrote the file.)
#
# This directory must live in the repo directory so that cmd/worker/Dockerfile
# can access it.
go-vulndb:
	gsutil -m -q cp -r gs://go-vulndb .
	gsutil stat gs://go-vulndb/index.json | \
		awk '$$1 == "Update" { for (i = 4; i <= NF; i++) printf("%s ", $$i); printf("\n"); }' \
		> go-vulndb/LAST_MODIFIED

# Remove comments from a json file.
%.json: %.json.commented
	sed '/^[ \t]*#/d' $< > $@

IMAGE := ecosystem-worker-test
DOCKER_RUN_ARGS := --rm --privileged -p 8080:8080
DOCKER_ID_FILE := /tmp/ecosystem-docker-container-id


# Build a docker image for testing.
# This target is a local file that marks the time of the last
# docker build. We use a file because make uses only local file timestamps to determine
# whether a target needs to be regenerated.
docker-build: go-image.tar.gz go-vulndb cmd/worker/*.go internal/**/*.go cmd/vulncheck_sandbox/* config.json cmd/worker/Dockerfile
	docker build -f cmd/worker/Dockerfile -t $(IMAGE) . \
          --build-arg DOCKER_IMAGE=$(IMAGE) \
          --build-arg BQ_DATASET=disable
	touch $@


# Run the docker image locally, for testing.
# The worker will start and listen at port 8080.
docker-run: docker-build
	docker run $(DOCKER_RUN_ARGS) $(IMAGE)

# Run the docker image and enter an interactive shell.
# The worker does not start.
docker-run-shell: docker-build
	docker run -it $(DOCKER_RUN_ARGS) $(IMAGE) /bin/bash

# Run the docker image in the background, waiting until the server is ready.
docker-run-bg: docker-build
	docker run --detach $(DOCKER_RUN_ARGS) $(IMAGE) > $(DOCKER_ID_FILE)
	while ! curl -s --head http://localhost:8080 > /dev/null; do sleep 1; done

# Test by scanning a small module.
test: docker-run-bg
	curl -s 'http://localhost:8080/vulncheck/scan/github.com/fossas/fossa-cli@v1.1.10?importedby=1&serve=true' > /tmp/test.out
	docker container stop `cat $(DOCKER_ID_FILE)`
	if [[ `grep -c GO-2020-0016 /tmp/test.out` -ge 4 ]]; then \
	    echo PASS; \
	    rm /tmp/test.out; \
	else \
	    echo FAIL; \
	    echo "output in /tmp/test.out"; \
	    exit 1; \
	fi

clean:
	rm -f go-image.tar.gz
	rm -rf go-vulndb
	rm -f config.json
	rm -f vulncheck_sandbox

.PHONY: docker-run docker-run-bg test clean
