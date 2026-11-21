# make builds the Linux probes, then sandprobe with them embedded (UX-1).
.PHONY: all probes sandprobe poc test test-e2b-sdk
all: sandprobe

probes:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-X main.BuildVersion=0.2.0" -o internal/probes/bin/sandprobe-probe-linux-amd64 ./cmd/sandprobe-probe
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags "-X main.BuildVersion=0.2.0" -o internal/probes/bin/sandprobe-probe-linux-arm64 ./cmd/sandprobe-probe
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o internal/probes/bin/sandprobe-canary-linux-amd64 ./cmd/sandprobe-canary
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -o internal/probes/bin/sandprobe-canary-linux-arm64 ./cmd/sandprobe-canary

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
