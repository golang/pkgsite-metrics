# Copyright 2023 The Go Authors. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

# Makefile for common tasks.

default:
	@echo "usage: make TARGET"

# Copy a gzipped tar of a Go docker image from a bucket.
# This is the image that is used by the sandbox.
# The file must live in the repo directory so that cmd/worker/Dockerfile
# can access it.
# We assume that the file exists in the bucket. 
# See the rule below for how to create the image.
go-image.tar.gz:
	gsutil cp gs://go-ecosystem/$@ $@

# Use this rule to build a go image for a specific Go version.
# E.g.
#	make go-image-1.19.4.tar.gz
# To change the sandbox image permanently, copy it to GCP:
#
#	gsutil cp go-image.1.19.4.tar.gz gs://go-ecosystem/go-image.tar.gz
# Then delete the local copy.
go-image-%.tar.gz:
	docker create golang:$* | gzip > go-image-$*.tar.gz

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

# Enable the docker container to authenticate to Google Cloud.
# This assumes the user has run "gcloud auth application-default login".
DOCKER_AUTH_ARGS := -v "$(HOME)/.config/gcloud:/creds" \
	--env GOOGLE_APPLICATION_CREDENTIALS=/creds/application_default_credentials.json

DOCKER_RUN_ARGS := --rm --privileged -p 8080:8080 \
	--env GO_ECOSYSTEM_BINARY_BUCKET=go-ecosystem \
	$(DOCKER_AUTH_ARGS)

DOCKER_ID_FILE := /tmp/ecosystem-docker-container-id


# Build a docker image for testing.
# This target is a local file that marks the time of the last
# docker build. We use a file because make uses only local file timestamps to determine
# whether a target needs to be regenerated.
docker-build: go-image.tar.gz go-vulndb cmd/worker/*.go internal/**/*.go cmd/govulncheck_sandbox/* config.json cmd/worker/Dockerfile
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

test: docker-run-bg govulncheck-test analysis-test
	docker container stop `cat $(DOCKER_ID_FILE)`

GOVULNCHECK_TEST_FILE := /tmp/vtest.out

# Test by scanning a small module.
govulncheck-test:
	curl -s 'http://localhost:8080/govulncheck/scan/github.com/fossas/fossa-cli@v1.1.10?importedby=1&serve=true' > $(GOVULNCHECK_TEST_FILE)
	@if [[ `grep -c GO-2020-0016 $(GOVULNCHECK_TEST_FILE)` -ge 4 ]]; then \
	    echo PASS; \
	    rm $(GOVULNCHECK_TEST_FILE); \
	else \
	    echo FAIL; \
	    echo "output in $(GOVULNCHECK_TEST_FILE)"; \
	    docker container stop `cat $(DOCKER_ID_FILE)`; \
	    exit 1; \
	fi

ANALYSIS_TEST_FILE := /tmp/atest.out

analysis-test:
	curl -sa 'http://localhost:8080/analysis/scan/github.com/jba/cli@v0.6.0?binary=findcall&args=-name+stringsCut&serve=true' > $(ANALYSIS_TEST_FILE)
	@if grep -q Diagnostics $(ANALYSIS_TEST_FILE); then \
	    echo PASS; \
	    rm $(ANALYSIS_TEST_FILE); \
	else \
	    echo FAIL; \
	    echo "output in $(ANALYSIS_TEST_FILE)"; \
	    docker container stop `cat $(DOCKER_ID_FILE)`; \
	    exit 1; \
	fi

clean:
	rm -f go-image.tar.gz
	rm -rf go-vulndb
	rm -f config.json
	rm -f govulncheck_sandbox

.PHONY: docker-run docker-run-bg test govulncheck-test analysis-test \
	clean build-go-image
