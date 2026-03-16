GO ?= go
TOOLS_MOD := -modfile=go.tools.mod
EXECUTABLE := authgate
GOFILES := $(shell find . -type f -name "*.go")
TAGS ?=

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

LDFLAGS ?= -X 'github.com/go-authgate/authgate/internal/version.Version=$(VERSION)' \
	-X 'github.com/go-authgate/authgate/internal/version.BuildTime=$(shell date +%Y-%m-%dT%H:%M:%S)' \
	-X 'github.com/go-authgate/authgate/internal/version.GitCommit=$(shell git rev-parse HEAD)' \
	-X 'github.com/go-authgate/authgate/internal/version.GoVersion=$(shell $(GO) version | cut -d " " -f 3)' \
	-X 'github.com/go-authgate/authgate/internal/version.BuildOS=$(shell $(GO) env GOOS)' \
	-X 'github.com/go-authgate/authgate/internal/version.BuildArch=$(shell $(GO) env GOARCH)'

all: generate build

## build: build the authgate binary
build: $(EXECUTABLE)

$(EXECUTABLE): $(GOFILES)
	$(GO) build -v -tags '$(TAGS)' -ldflags '$(EXTLDFLAGS)-s -w $(LDFLAGS)' -o bin/$@ .

## air: Install air for hot reload.
air:
	@hash air > /dev/null 2>&1; if [ $$? -ne 0 ]; then \
		$(GO) install github.com/air-verse/air@latest; \
	fi

## dev: Run the application with hot reload.
dev: air
	air

## build-all: build authgate binary
build-all: build

## install: install the authgate binary
install: $(GOFILES)
	$(GO) install -v -tags '$(TAGS)' -ldflags '$(EXTLDFLAGS)-s -w $(LDFLAGS)'

## test: run tests
test: generate
	@$(GO) test -v -cover -coverprofile coverage.txt ./... && echo "\n==>\033[32m Ok\033[m\n" || exit 1

## coverage: view test coverage in browser
coverage: test
	$(GO) tool cover -html=coverage.txt

## fmt: format go files using golangci-lint
fmt:
	$(GO) tool $(TOOLS_MOD) golangci-lint fmt

## lint: run golangci-lint to check for issues
lint:
	$(GO) tool $(TOOLS_MOD) golangci-lint run

## build_linux_amd64: build the authgate binary for linux amd64
build_linux_amd64: generate
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -a -tags '$(TAGS)' -ldflags '$(EXTLDFLAGS)-s -w $(LDFLAGS)' -o release/linux/amd64/$(EXECUTABLE) .

## build_linux_arm64: build the authgate binary for linux arm64
build_linux_arm64: generate
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build -a -tags '$(TAGS)' -ldflags '$(EXTLDFLAGS)-s -w $(LDFLAGS)' -o release/linux/arm64/$(EXECUTABLE) .

## build_all_linux_amd64: build authgate binary for linux amd64
build_all_linux_amd64: build_linux_amd64

## build_all_linux_arm64: build authgate binary for linux arm64
build_all_linux_arm64: build_linux_arm64

## assets: build and minify static assets (production)
assets:
	$(GO) run $(TOOLS_MOD) scripts/build_assets.go --minify

## assets-dev: build static assets without minification (development)
assets-dev:
	$(GO) run $(TOOLS_MOD) scripts/build_assets.go

## clean: remove build artifacts and test coverage
clean:
	rm -rf bin/ release/ coverage.txt internal/templates/static/dist/ internal/gen/
	find internal/templates -name "*_templ.go" -delete
	rm -f internal/templates/asset_paths.go

## rebuild: clean and build
rebuild: clean build

.PHONY: help build build-all install test coverage fmt lint clean rebuild
.PHONY: build_linux_amd64 build_linux_arm64
.PHONY: build_all_linux_amd64 build_all_linux_arm64 generate watch air dev mocks
.PHONY: install-tools mod-download mod-tidy mod-verify check-tools version
.PHONY: docker-build docker-run swagger swagger-init swagger-fmt swagger-validate
.PHONY: assets assets-dev proto proto-lint

## install-tools: download tool dependencies
install-tools:
	$(GO) mod download $(TOOLS_MOD)

## proto: generate protobuf and connect-go code
proto:
	buf generate

## proto-lint: lint protobuf definitions
proto-lint:
	buf lint

## generate: run go generate (templ compilation + mocks via go:generate directives)
generate: install-tools assets swagger proto
	$(GO) generate ./...

## mocks: generate mock files only (all directives in internal/mocks/)
mocks:
	$(GO) generate ./internal/mocks/

## watch: watch mode for automatic regeneration
watch:
	$(GO) tool $(TOOLS_MOD) templ generate --watch

## help: print this help message
help:
	@echo 'Usage:'
	@sed -n 's/^##//p' ${MAKEFILE_LIST} | column -t -s ':' | sed -e 's/^/ /'

## mod-download: download go module dependencies
mod-download:
	$(GO) mod download

## mod-tidy: tidy go module dependencies
mod-tidy:
	$(GO) mod tidy

## mod-verify: verify go module dependencies
mod-verify:
	$(GO) mod verify

## check-tools: verify Go is installed (tools are managed via modfile)
check-tools:
	@command -v $(GO) >/dev/null 2>&1 || (echo "Go not found" && exit 1)

## version: display version information
version:
	@echo "Version: $(VERSION)"
	@echo "Commit: $(COMMIT)"
	@echo "Go Version: $(shell $(GO) version)"

## docker-build: build docker image
docker-build:
	docker build -t authgate:$(VERSION) -f Dockerfile .

## docker-run: run docker container
docker-run:
	docker run -p 8080:8080 --env-file .env authgate:$(VERSION)

## swagger-init: generate swagger documentation
swagger-init:
	$(GO) tool $(TOOLS_MOD) swag init -g main.go --output api --parseDependency --parseInternal

## swagger: alias for swagger-init
swagger: swagger-init

## swagger-fmt: format swagger comments
swagger-fmt:
	$(GO) tool $(TOOLS_MOD) swag fmt

## swagger-validate: validate swagger documentation
swagger-validate: swagger-init
	@echo "Swagger documentation generated successfully in api/"
	@test -f api/swagger.json && echo "swagger.json: OK" || (echo "swagger.json: MISSING" && exit 1)
	@test -f api/swagger.yaml && echo "swagger.yaml: OK" || (echo "swagger.yaml: MISSING" && exit 1)
