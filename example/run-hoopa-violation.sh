#!/usr/bin/env bash
set -euo pipefail

RUNTIME_ENDPOINT="${RUNTIME_ENDPOINT:-}"
IMAGE="${IMAGE:-busybox:latest}"
NAMESPACE="${NAMESPACE:-default}"
POD_NAME="${POD_NAME:-hoopa}"
CONTAINER_NAME="${CONTAINER_NAME:-hoopa}"

if ! command -v crictl >/dev/null 2>&1; then
  echo "crictl is required but was not found in PATH" >&2
  exit 1
fi

if [[ -z "${RUNTIME_ENDPOINT}" ]]; then
  for socket in \
    /run/k3s/containerd/containerd.sock \
    /run/containerd/containerd.sock \
    /run/crio/crio.sock \
    /var/run/cri-dockerd.sock
  do
    if [[ -S "${socket}" ]]; then
      RUNTIME_ENDPOINT="unix://${socket}"
      break
    fi
  done
fi

if [[ -z "${RUNTIME_ENDPOINT}" ]]; then
  echo "could not find a CRI runtime socket; set RUNTIME_ENDPOINT=unix:///path/to/socket" >&2
  exit 1
fi

WORKDIR="$(mktemp -d)"
APPDIR="${WORKDIR}/app"
SECRETSDIR="${APPDIR}/secrets"
POD_CONFIG="${WORKDIR}/pod-config.json"
CONTAINER_CONFIG="${WORKDIR}/container-config.json"
POD_ID=""
CONTAINER_ID=""

cleanup() {
  set +e
  if [[ -n "${CONTAINER_ID}" ]]; then
    crictl --runtime-endpoint "${RUNTIME_ENDPOINT}" stop "${CONTAINER_ID}" >/dev/null 2>&1 || true
    crictl --runtime-endpoint "${RUNTIME_ENDPOINT}" rm "${CONTAINER_ID}" >/dev/null 2>&1 || true
  fi
  if [[ -n "${POD_ID}" ]]; then
    crictl --runtime-endpoint "${RUNTIME_ENDPOINT}" stopp "${POD_ID}" >/dev/null 2>&1 || true
    crictl --runtime-endpoint "${RUNTIME_ENDPOINT}" rmp "${POD_ID}" >/dev/null 2>&1 || true
  fi
  rm -rf "${WORKDIR}"
}
trap cleanup EXIT

mkdir -p "${SECRETSDIR}"

cat > "${APPDIR}/hoopa.sh" <<'EOF'
#!/bin/sh
cat /app/secrets/secret.txt
EOF
chmod 0755 "${APPDIR}/hoopa.sh"

cat > "${SECRETSDIR}/secret.txt" <<'EOF'
super secret demo data
EOF
chmod 0644 "${SECRETSDIR}/secret.txt"

cat > "${POD_CONFIG}" <<EOF
{
  "metadata": {
    "name": "${POD_NAME}",
    "namespace": "${NAMESPACE}",
    "attempt": 1
  },
  "labels": {
    "io.kubernetes.pod.name": "${POD_NAME}",
    "io.kubernetes.pod.namespace": "${NAMESPACE}"
  },
  "log_directory": "/tmp"
}
EOF

cat > "${CONTAINER_CONFIG}" <<EOF
{
  "metadata": {
    "name": "${CONTAINER_NAME}"
  },
  "image": {
    "image": "${IMAGE}"
  },
  "command": ["cat", "/app/secrets/secret.txt"],
  "labels": {
    "io.kubernetes.pod.name": "${POD_NAME}",
    "io.kubernetes.pod.namespace": "${NAMESPACE}",
    "io.kubernetes.container.name": "${CONTAINER_NAME}"
  },
  "mounts": [
    {
      "container_path": "/app",
      "host_path": "${APPDIR}",
      "readonly": true
    }
  ],
  "log_path": "${CONTAINER_NAME}.log"
}
EOF

echo "Using runtime endpoint: ${RUNTIME_ENDPOINT}"
echo "Pulling image: ${IMAGE}"
crictl --runtime-endpoint "${RUNTIME_ENDPOINT}" pull "${IMAGE}" >/dev/null

echo "Creating pod sandbox ${NAMESPACE}/${POD_NAME}"
POD_ID="$(crictl --runtime-endpoint "${RUNTIME_ENDPOINT}" runp "${POD_CONFIG}" | tail -n 1)"

echo "Creating container ${CONTAINER_NAME}"
CONTAINER_ID="$(crictl --runtime-endpoint "${RUNTIME_ENDPOINT}" create "${POD_ID}" "${CONTAINER_CONFIG}" "${POD_CONFIG}" | tail -n 1)"

echo "Starting container ${CONTAINER_NAME}"
crictl --runtime-endpoint "${RUNTIME_ENDPOINT}" start "${CONTAINER_ID}" >/dev/null

sleep 1

echo
echo "Container logs:"
crictl --runtime-endpoint "${RUNTIME_ENDPOINT}" logs "${CONTAINER_ID}" || true
echo
echo "If bomfather is enforcing example/config.yaml, this cat access should be denied because only /app/hoopa.sh is allowed to read /app/secrets."
