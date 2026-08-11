# syntax=docker/dockerfile:1.7

# Build stage: compiles the eBPF object, generated protobuf code, and the
# static Go binary.
FROM golang:1.26.5-bookworm AS builder

# Tools required to build the embedded eBPF object and generated protobuf code.
# Bookworm ships clang/llvm 14 via the unversioned meta-packages, which provide
# the `clang` and `llvm-objcopy` binaries the Makefile invokes.
RUN apt-get update \
	&& apt-get install -y --no-install-recommends \
		clang \
		llvm \
		llvm-14 \
		protobuf-compiler \
	&& rm -rf /var/lib/apt/lists/* \
	&& command -v clang \
	&& command -v llvm-objcopy

WORKDIR /src

# Cache module/vendor layers independently of the source tree.
COPY go.mod go.sum ./
COPY vendor/ ./vendor/
COPY Makefile ./

# Install the pinned protoc Go plugins via the Makefile (single source of
# truth for tool versions). The golang image puts $GOPATH/bin on PATH, so
# `protoc` finds the plugins during `make build`.
RUN make tools

# Copy the rest of the source, including the libbpf submodule under bpf/libbpf.
COPY . .

# Build everything: embedded BPF object, generated protobuf code, and the
# static agent binary. CGO is disabled so the result is fully static.
RUN make build

# Runtime stage: distroless/static is a minimal, shell-less, static-binary
# image with no package manager or OS utilities. Use the root variant (not
# :nonroot) so the agent can load eBPF programs without permission errors.
FROM gcr.io/distroless/static-debian12

COPY --from=builder /src/agent /agent

# The agent uses eBPF and needs to run as root (or with elevated capabilities).
# The container runtime is responsible for granting required capabilities;
# the image itself stays minimal.
ENTRYPOINT ["/agent"]
