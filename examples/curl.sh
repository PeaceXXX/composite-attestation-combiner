#!/usr/bin/env bash
# End-to-end example against a locally running server.
# Prerequisites: go run ./cmd/keygen inference-worker-01 && export KMS_MASTER_KEY=...
set -euo pipefail

BASE="${BASE:-http://localhost:8080}"

echo "== health =="
curl -s "$BASE/v1/healthz"; echo

echo "== attest (pass sample) =="
go run ./cmd/demo --print-request pass > /tmp/req.json
curl -s -X POST "$BASE/v1/attest" -H 'Content-Type: application/json' \
  -d @/tmp/req.json | python3 -m json.tool

echo "== attest (tampered-cpu sample) =="
go run ./cmd/demo --print-request tampered-cpu > /tmp/req-bad.json
curl -s -X POST "$BASE/v1/attest" -H 'Content-Type: application/json' \
  -d @/tmp/req-bad.json | python3 -m json.tool

echo "== audit =="
curl -s "$BASE/v1/audit" | python3 -m json.tool
