GO ?= go
EXECUTABLE := authgate
EXECUTABLE_CLI := authgate-cli
GOFILES := $(shell find . -type f -name "*.go")
TAGS ?=
TEMPL_VERSION ?= latest

ifneq ($(shell uname), Darwin)
	EXTLDFLAGS = -extldflags "-static" $(null)
else
	EXTLDFLAGS =
endif

ifneq ($(DRONE_TAG),)
	VERSION ?= $(DRONE_TAG)
else
	VERSION ?= $(shell git describe --tags --always || git rev-parse --short HEAD)
endif
COMMIT ?= $(shell git rev-parse --short HEAD)

LDFLAGS ?= -X 'github.com/appleboy/authgate/internal/version.Version=$(VERSION)' \
	-X 'github.com/appleboy/authgate/internal/version.BuildTime=$(shell date +%Y-%m-%dT%H:%M:%S)' \
	-X 'github.com/appleboy/authgate/internal/version.GitCommit=$(shell git rev-parse HEAD)' \
	-X 'github.com/appleboy/authgate/internal/version.GoVersion=$(shell $(GO) version | cut -d " " -f 3)' \
	-X 'github.com/appleboy/authgate/internal/version.BuildOS=$(shell $(GO) env GOOS)' \
	-X 'github.com/appleboy/authgate/internal/version.BuildArch=$(shell $(GO) env GOARCH)'

## install-templ: install templ CLI if not installed
install-templ:
	@command -v templ >/dev/null 2>&1 || $(GO) install github.com/a-h/templ/cmd/templ@$(TEMPL_VERSION)

## generate: run templ generate to compile .templ files
generate: install-templ
	templ generate

## watch: watch mode for automatic regeneration
watch: install-templ
	templ generate --watch

## build: build the authgate binary
build: generate $(EXECUTABLE)

$(EXECUTABLE): $(GOFILES)
	$(GO) build -v -tags '$(TAGS)' -ldflags '$(EXTLDFLAGS)-s -w $(LDFLAGS)' -o bin/$@ .

## build-cli: build the authgate-cli binary
build-cli: $(EXECUTABLE_CLI)

$(EXECUTABLE_CLI):
	cd _example/authgate-cli && $(GO) build -v -o ../../bin/$@ .

## build-all: build both authgate and authgate-cli binaries
build-all: build build-cli

## install: install the authgate binary
install: $(GOFILES)
	$(GO) install -v -tags '$(TAGS)' -ldflags '$(EXTLDFLAGS)-s -w $(LDFLAGS)'

## test: run tests
test:
	@$(GO) test -v -cover -coverprofile coverage.txt ./... && echo "\n==>\033[32m Ok\033[m\n" || exit 1

## fmt: format go files using golangci-lint
fmt:
	@command -v golangci-lint >/dev/null 2>&1 || curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/HEAD/install.sh | sh -s -- -b $$($(GO) env GOPATH)/bin v2.7.2
	golangci-lint fmt

## lint: run golangci-lint to check for issues
lint:
	@command -v golangci-lint >/dev/null 2>&1 || curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/HEAD/install.sh | sh -s -- -b $$($(GO) env GOPATH)/bin v2.7.2
	golangci-lint run

## build_linux_amd64: build the authgate binary for linux amd64
build_linux_amd64:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -a -tags '$(TAGS)' -ldflags '$(EXTLDFLAGS)-s -w $(LDFLAGS)' -o release/linux/amd64/$(EXECUTABLE) .

## build_linux_arm64: build the authgate binary for linux arm64
build_linux_arm64:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build -a -tags '$(TAGS)' -ldflags '$(EXTLDFLAGS)-s -w $(LDFLAGS)' -o release/linux/arm64/$(EXECUTABLE) .

## build_cli_linux_amd64: build the authgate-cli binary for linux amd64
build_cli_linux_amd64:
	cd _example/authgate-cli && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -a -o ../../release/linux/amd64/$(EXECUTABLE_CLI) .

## build_cli_linux_arm64: build the authgate-cli binary for linux arm64
build_cli_linux_arm64:
	cd _example/authgate-cli && CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build -a -o ../../release/linux/arm64/$(EXECUTABLE_CLI) .

## build_all_linux_amd64: build both binaries for linux amd64
build_all_linux_amd64: build_linux_amd64 build_cli_linux_amd64

## build_all_linux_arm64: build both binaries for linux arm64
build_all_linux_arm64: build_linux_arm64 build_cli_linux_arm64

## clean: remove build artifacts and test coverage
clean:
	rm -rf bin/ release/ coverage.txt
	find internal/templates -name "*_templ.go" -delete

.PHONY: help build build-cli build-all install test fmt lint clean
.PHONY: build_linux_amd64 build_linux_arm64 build_cli_linux_amd64 build_cli_linux_arm64
.PHONY: build_all_linux_amd64 build_all_linux_arm64 install-templ generate watch

## help: print this help message
help:
	@echo 'Usage:'
	@sed -n 's/^##//p' ${MAKEFILE_LIST} | column -t -s ':' | sed -e 's/^/ /'
