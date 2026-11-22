# make builds the Linux probes, then sandprobe with them embedded (UX-1).
.PHONY: all probes sandprobe poc test test-e2b-sdk release
all: sandprobe

# The one version, read from the CLI: the probe's BuildVersion and every release use it (REL-1, REL-2).
VERSION := $(shell sed -n 's/^const Version = "\(.*\)"$$/\1/p' cmd/sandprobe/main.go)
# Deterministic: no paths, no VCS stamp (REL-1).
GOFLAGS_REPRO := -trimpath -buildvcs=false

probes:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build $(GOFLAGS_REPRO) -ldflags "-X main.BuildVersion=$(VERSION)" -o internal/probes/bin/sandprobe-probe-linux-amd64 ./cmd/sandprobe-probe
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build $(GOFLAGS_REPRO) -ldflags "-X main.BuildVersion=$(VERSION)" -o internal/probes/bin/sandprobe-probe-linux-arm64 ./cmd/sandprobe-probe
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build $(GOFLAGS_REPRO) -o internal/probes/bin/sandprobe-canary-linux-amd64 ./cmd/sandprobe-canary
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build $(GOFLAGS_REPRO) -o internal/probes/bin/sandprobe-canary-linux-arm64 ./cmd/sandprobe-canary

sandprobe: probes
	go build -trimpath -o bin/sandprobe ./cmd/sandprobe

# poc builds the Modal proof of concept's helper and a sandprobe with the poc command (POC-1); never a release.
poc: probes
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o cmd/sandprobe/pocbin/sandprobe-aux-linux-amd64 ./cmd/sandprobe-aux
	go build -trimpath -tags poc -o bin/sandprobe-poc ./cmd/sandprobe

test:
	go vet ./... && go test ./...

# Offline SDK contract tests, with the pinned requirements preinstalled in a venv.
test-e2b-sdk:
	"$${SANDPROBE_E2B_PYTHON:-python3}" -I internal/host/e2b_runtime_test.py

# Offline pinned Daytona SDK contracts.
test-daytona-sdk:
	"$${SANDPROBE_DAYTONA_PYTHON:-python3}" -I internal/host/daytona_runtime_test.py

# Local artifacts only; no remote installer or release publication (QCK-2).
.PHONY: package
package: sandprobe
	mkdir -p bin/package
	cp internal/probes/bin/sandprobe-probe-linux-amd64 internal/probes/bin/sandprobe-probe-linux-arm64 bin/package/
	cd bin/package && shasum -a 256 sandprobe-probe-linux-amd64 sandprobe-probe-linux-arm64 > SHA256SUMS

# release builds what a release ships into bin/release: four sandprobe binaries, gzipped, with SHA256SUMS over the
# .gz files and SHA256SUMS-binaries over the binaries. Every file is written or overwritten by name. The release
# workflow builds it twice and publishes only on a byte-for-byte match (REL-1, REL-2).
RELEASE_FILES := sandprobe-darwin-arm64 sandprobe-darwin-amd64 sandprobe-linux-arm64 sandprobe-linux-amd64
release: probes
	mkdir -p bin/release
	for f in $(RELEASE_FILES); do \
	  os=$$(echo $$f | cut -d- -f2); arch=$$(echo $$f | cut -d- -f3); \
	  CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build $(GOFLAGS_REPRO) -ldflags "-s -w" -o bin/release/$$f ./cmd/sandprobe || exit 1; \
	done
	cd bin/release && shasum -a 256 $(RELEASE_FILES) > SHA256SUMS-binaries
	cd bin/release && for f in $(RELEASE_FILES); do gzip -9 -n -f $$f || exit 1; done
	cd bin/release && shasum -a 256 $(addsuffix .gz,$(RELEASE_FILES)) > SHA256SUMS
