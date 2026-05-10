## SOTH ops Makefile — thin dispatcher.
##
## All logic lives in `ops/release.sh`; this file is just the verb surface so
## the conventional `make <target> ENV=…` workflow keeps working. The
## delegation pattern dodges GNU Make 3.81's lack of `.ONESHELL:` (Apple's
## bundled make) and keeps the per-recipe shell quoting sane.
##
## Phase 1 covers CLI binaries; Phase 2 (classify bundle) and Phase 3 (tool
## catalog) extend `ops/release.sh` with new verbs.

SHELL := /usr/bin/env bash
ENV ?= staging

# Pass --quiet to avoid double-printing the recipe; ops/release.sh has its
# own progress output.
.SILENT:

OPS := ./ops/release.sh

.PHONY: help
help:
	$(OPS) help

.PHONY: build-cli publish-cli release-cli verify-cli diff
build-cli:
	$(OPS) build-cli '$(ENV)'

publish-cli:
	$(OPS) publish-cli '$(ENV)'

release-cli:
	$(OPS) release-cli '$(ENV)'

verify-cli:
	$(OPS) verify-cli '$(ENV)'

diff:
	$(OPS) diff '$(ENV)'

.PHONY: generate-manifest sign-manifest publish-manifest verify-manifest register-release
generate-manifest:
	$(OPS) generate-manifest '$(ENV)'

sign-manifest:
	$(OPS) sign-manifest '$(ENV)'

publish-manifest:
	$(OPS) publish-manifest '$(ENV)'

verify-manifest:
	$(OPS) verify-manifest '$(ENV)'

register-release:
	$(OPS) register-release '$(ENV)'

.PHONY: build-classify publish-classify release-classify verify-classify
build-classify:
	$(OPS) build-classify '$(ENV)'

publish-classify:
	$(OPS) publish-classify '$(ENV)'

release-classify:
	$(OPS) release-classify '$(ENV)'

verify-classify:
	$(OPS) verify-classify '$(ENV)'

.PHONY: import-catalog compile-catalog publish-catalog release-catalog
import-catalog:
	$(OPS) import-catalog '$(ENV)'

compile-catalog:
	$(OPS) compile-catalog '$(ENV)'

publish-catalog:
	$(OPS) publish-catalog '$(ENV)'

release-catalog:
	$(OPS) release-catalog '$(ENV)'

.PHONY: status status-all
status:
	$(OPS) status '$(ENV)'

status-all:
	$(OPS) status-all

.PHONY: clean-dist
clean-dist:
	$(OPS) clean-dist
