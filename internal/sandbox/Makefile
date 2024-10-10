# Copyright 2022 The Go Authors. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

# Makefile for the sandbox package.
# `make` will build and install binaries needed for the test, run the test as root,
# then clean up.

default: test clean

test: /usr/local/bin/runsc testbundle
	sudo RUN_FROM_MAKE=1 $(shell which go) test -v


# Release version must match the one in cmd/worker/Dockerfile.
RUNSC_URL := https://storage.googleapis.com/gvisor/releases/release/20240930.0/$(shell uname -m)

# This is an edited version of the commands at https://gvisor.dev/docs/user_guide/install.
/usr/local/bin/runsc:
	wget $(RUNSC_URL)/runsc $(RUNSC_URL)/runsc.sha512
	sha512sum -c runsc.sha512
	rm -f *.sha512
	chmod a+rx runsc
	sudo mv runsc /usr/local/bin

testbundle: testdata/bundle/rootfs/runner testdata/bundle/rootfs/printargs
	chmod o+rx testdata/bundle/rootfs

testdata/bundle/rootfs/runner: runner.go
	go build -o $@ $<
	chmod o+rx $@

testdata/bundle/rootfs/printargs: testdata/printargs.go
	go build -o $@ $<
	chmod o+rx $@

clean:
	rm testdata/bundle/rootfs/runner
	rm testdata/bundle/rootfs/printargs

.PHONY: clean testbundle

