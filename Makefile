SHELL := /bin/sh
MODULE := github.com/tomkabel/eidbridge
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
GOBIN_DIR ?= $(shell go env GOPATH)/bin
LDFLAGS := -s -w -X $(MODULE)/internal/version.Version=$(VERSION)
PLATFORMS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64

.PHONY: fmt-check vet test build cross licenses licenses-report spec-pins arch-trace gitleaks image sbom check clean

fmt-check:
	@out="$$(gofmt -l .)"; \
	if [ -n "$$out" ]; then echo "gofmt needed on:"; echo "$$out"; exit 1; fi

vet:
	go vet ./...

test:
	go test -race -count=1 ./...

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/eidbridge ./cmd/eidbridge

cross:
	@set -eu; \
	rm -rf dist; mkdir -p dist; \
	for p in $(PLATFORMS); do \
		os="$${p%/*}"; arch="$${p#*/}"; \
		echo "building dist/eidbridge_$${os}_$${arch}"; \
		CGO_ENABLED=0 GOOS="$$os" GOARCH="$$arch" go build -trimpath -ldflags "$(LDFLAGS)" -o "dist/eidbridge_$${os}_$${arch}" ./cmd/eidbridge; \
	done; \
	cd dist; \
	if command -v sha256sum >/dev/null 2>&1; then sha256sum eidbridge_* > checksums.txt; \
	else shasum -a 256 eidbridge_* > checksums.txt; fi; \
	if command -v file >/dev/null 2>&1; then \
		for f in eidbridge_linux_*; do file "$$f"; done; \
	fi

licenses:
	$(GOBIN_DIR)/go-licenses check ./... --disallowed_types=forbidden,restricted,reciprocal,unknown

licenses-report:
	@mkdir -p dist
	$(GOBIN_DIR)/go-licenses report ./... > dist/licenses.csv

spec-pins:
	python3 scripts/check_spec_pins.py

arch-trace:
	python3 tools/check-arch-trace

gitleaks:
	$(GOBIN_DIR)/gitleaks git --redact --no-banner .

image:
	docker build -t eidbridge:local --build-arg VERSION=$(VERSION) .
	docker image inspect eidbridge:local --format '{{.Size}}'
	docker image inspect eidbridge:local --format '{{.Config.User}}'

sbom:
	@mkdir -p dist
	@if command -v syft >/dev/null 2>&1; then \
		syft dir:. -o spdx-json > dist/sbom.spdx.json; \
	else \
		[ -f bin/eidbridge ] || $(MAKE) build; \
		go version -m bin/eidbridge | python3 -c 'import json,sys; ds=[l.split() for l in sys.stdin if l.startswith("\tdep")]; json.dump({"bomFormat":"CycloneDX","specVersion":"1.5","components":[{"type":"library","name":p[1],"version":p[2],"hashes":[{"alg":"SHA-256","content":p[3]}] if len(p)>3 else []} for p in ds if len(p)>=3]},open("dist/sbom.json","w"),indent=2)'; \
	fi

check: fmt-check vet test licenses spec-pins arch-trace

clean:
	rm -rf bin dist
