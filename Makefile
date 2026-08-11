BIN := agent
BPF_OBJ := bpf/trace.o
PROTO_FILE := proto/ingestion.proto
PROTO_GEN := proto/ingestion.pb.go proto/ingestion_grpc.pb.go
LIBBPF_HEADER := bpf/libbpf/src/bpf_helpers.h

VERSION_PKG := github.com/bomfather/bomfather/agent/grpcclient
VERSION := $(shell git describe --tags 2>/dev/null || echo dev)
COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
LDFLAGS := -s -w \
	-X '$(VERSION_PKG).Version=$(VERSION)' \
	-X '$(VERSION_PKG).Commit=$(COMMIT)'

GO := go
GOFLAGS := CGO_ENABLED=0
MOD := -mod=vendor
CI_PACKAGES := ./grpcclient ./secureshutdown ./cri

# Pinned versions of the protoc Go plugins used by the `proto` target.
PROTOC_GEN_GO_VERSION := v1.36.5
PROTOC_GEN_GO_GRPC_VERSION := v1.5.1

.PHONY: all build $(BIN) bpf proto tools init test coverage coverage-ci coverage-full ci test-integration tidy vendor fmt clean \
	build-agent build-bpf build-proto docker

all: build

# `tools` is idempotent and cheap (a `command -v` check), so pulling it in
# here guarantees the protoc plugins are present for any build path,
# including `make ci` on a fresh clone without a separate `make tools` step.
build: tools $(BIN)

$(BIN): $(BPF_OBJ) $(PROTO_GEN)
	# Always rebuild the Go binary; Go will still reuse its own build cache.
	$(GOFLAGS) $(GO) build $(MOD) -ldflags="$(LDFLAGS)" -o $(BIN) main.go

bpf: $(BPF_OBJ)

$(BPF_OBJ): bpf/trace.c
	@test -f $(LIBBPF_HEADER) || git submodule update --init --recursive
	clang -O2 -g -target bpf -I bpf/libbpf/src -c $< -o $@
	llvm-objcopy --strip-debug $@

proto: tools $(PROTO_GEN)

$(PROTO_GEN): $(PROTO_FILE)
	protoc --go_out=. --go_opt=paths=source_relative \
		--go-grpc_out=. --go-grpc_opt=paths=source_relative \
		$(PROTO_FILE)

# Install the protoc Go plugins required by `proto`. Idempotent: only
# installs a plugin if it is not already on PATH.
tools:
	@command -v protoc-gen-go >/dev/null 2>&1 || \
		$(GO) install google.golang.org/protobuf/cmd/protoc-gen-go@$(PROTOC_GEN_GO_VERSION)
	@command -v protoc-gen-go-grpc >/dev/null 2>&1 || \
		$(GO) install google.golang.org/grpc/cmd/protoc-gen-go-grpc@$(PROTOC_GEN_GO_GRPC_VERSION)

init:
	git submodule update --init --recursive

test:
	$(GOFLAGS) $(GO) test $(MOD) -v ./...

coverage-ci:
	$(GOFLAGS) $(GO) test $(MOD) $(CI_PACKAGES) -coverprofile=coverage.out -covermode=atomic

coverage-full: bpf
	$(GOFLAGS) $(GO) test $(MOD) ./... -coverprofile=coverage.out -covermode=atomic

coverage:
	@packages='$(CI_PACKAGES)'; \
	if [ "$$(uname -s)" = "Linux" ] && [ -z "$$CI" ] && $(MAKE) -s bpf 2>/dev/null; then \
		packages='./...'; \
	fi; \
	$(GOFLAGS) $(GO) test $(MOD) $$packages -coverprofile=coverage.out -covermode=atomic

ci: build coverage-ci

test-integration: build
	sudo $(GOFLAGS) $(GO) test $(MOD) -tags=integration -timeout=20m -v ./integration

tidy: proto
	go mod tidy
	go mod vendor

vendor:
	go mod vendor

fmt:
	go fmt ./...

clean:
	rm -f $(BIN) $(BPF_OBJ) $(PROTO_GEN)

# Backward-compatible aliases
build-agent: build
build-bpf: bpf
build-proto: proto

DOCKER_IMAGE ?= bomfather/agent
DOCKER_TAG ?= dev

# Initialize the libbpf submodule on the host first so it is present in the
# build context. `.dockerignore` excludes `.git`, so the Makefile's
# in-container `git submodule` fallback cannot run; the submodule contents
# (bpf/libbpf/**) are copied in directly.
docker: init
	docker build -t $(DOCKER_IMAGE):$(DOCKER_TAG) .
