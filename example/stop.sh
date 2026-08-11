#!/usr/bin/env bash
set -euo pipefail

KEY_PATH="goodkeys/private.pem"
API="http://localhost:8089"

echo "Requesting shutdown nonce..."
NONCE=$(curl -sS -X POST "$API/request" | jq -r .nonce)

if [ -z "$NONCE" ]; then
  echo "Failed to get nonce from API."
  exit 1
fi

echo "Got nonce: $NONCE"
echo "Signing nonce with key: $KEY_PATH"

SIG=$(printf %s "$NONCE" \
  | openssl dgst -sha256 -sign "$KEY_PATH" \
  | base64 -w0)

echo "Sending shutdown request..."
curl -sS -X POST "$API/stop" \
  -H 'Content-Type: application/json' \
  -d "{\"nonce\":\"$NONCE\",\"signature\":\"$SIG\"}"
echo