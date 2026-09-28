# composite-attestation-combiner

A composite attestation evidence combiner for confidential inference: it
verifies **CPU TEE evidence** (Intel TDX-style quote: TCB version, TD
attributes, MRTD/RTMR measurements) and **GPU evidence** (NVIDIA-style
attestation report: driver version, firmware measurements) *together*, then
releases a workload's data-encryption key only when the combined verdict
passes.

## Why this exists

Confidential inference increasingly spans two TEEs: a CPU trust domain
(Intel TDX) and a confidential GPU (e.g. NVIDIA H100/H200 CC mode). Each
side has its own attestation evidence, but a key-release decision — "should
this worker get the model decryption key?" — is only meaningful if **both**
are evaluated as one unit:

- a valid GPU report stapled to a compromised CPU quote must not grant a key,
- a valid CPU quote stapled to a *different session's* GPU report (nonce
  splicing) must not grant a key,
- stale evidence must not be replayed for a fresh key.

This project implements that combiner as a small, readable Go service:
per-source verifiers, a composite policy engine, and a mock KMS with an
audit trail. It is the pattern behind confidential model-serving key
release, built with public concepts only.

## Architecture

```
                    +-------------------+
                    | inference worker  |
                    | (TDX TD + H100)   |
                    +--------+----------+
                             |  POST /v1/attest
                             |  { cpu quote, gpu report }
                             v
                    +-------------------+
                    |   attest handler  |  internal/server
                    +--------+----------+
                             |
              +--------------+--------------+
              |                             |
              v                             v
   +------------------+          +------------------+
   | policy.Combiner  |          |   keyrelease.KMS |
   +--------+---------+          +--------+---------+
            |                             |
   +--------+--------+                    | grant: unwrap + return key
   |                 |                    | deny:  return reasons
   v                 v                    v
+-------+      +-----------+     +------------------+
| CPU   |      | GPU       |     | audit log        |
| verif.|      | verifier  |     | (grant/deny,     |
+---+---+      +-----+-----+     |  newest last)    |
    |                  |         +------------------+
    v                  v
+---------------------------------------+
| reference manifest (golden values)    |
| internal/reference                    |
+---------------------------------------+

Combiner checks, in order:
  1. structural validation (evidence.Validate)
  2. freshness (issued_at within window — replay defense)
  3. per-source verification (CPU always; GPU iff workload uses_gpu)
  4. session binding (cpu.session_nonce == gpu.session_nonce — splice defense)
  5. score = weighted pass fraction over evaluated sources
```

## Quickstart

Requires Go 1.21+.

```bash
# 1. Run the offline demo — all six scenarios, no server needed
go run ./cmd/demo
```

Actual output:

```
SCENARIO       VERDICT  SCORE  NOTES
pass           GRANT    1.00   -
tampered-cpu   DENY     0.50   cpu verification failed
tampered-gpu   DENY     0.50   gpu verification failed
nonce-splice   DENY     1.00   cpu/gpu session_nonce mismatch: evidence is not bound to the same session
stale          DENY     1.00   evidence is stale (age exceeds freshness window)
cpu-only       GRANT    1.00   -
```

```bash
# 2. Provision demo keys (prints a throwaway KMS_MASTER_KEY — demo only)
go run ./cmd/keygen inference-worker-01
export KMS_MASTER_KEY=<printed hex>

# 3. Start the service
go run ./cmd/server          # listens on :8080

# 4. Attest a workload (fresh timestamp generated for you)
go run ./cmd/demo --print-request pass > /tmp/req.json
curl -s -X POST localhost:8080/v1/attest \
  -H 'Content-Type: application/json' -d @/tmp/req.json | python3 -m json.tool

# 5. Inspect the audit trail
curl -s localhost:8080/v1/audit | python3 -m json.tool
```

```bash
# Tests
go test ./...

# Docker
docker build -t composite-attestation-combiner .
docker run -e KMS_MASTER_KEY=... -p 8080:8080 composite-attestation-combiner
```

> The sample evidence in `data/samples/` and golden values in
> `data/reference-manifest.json` are fictional fixtures generated for this
> demo (see `docs/fixtures.md`). `issued_at` is normalized to "now" by the
> demo CLI; `stale.json` is deliberately backdated to exercise the
> freshness check.

## API reference

### `POST /v1/attest`

Request body — `AttestationRequest`:

| Field | Type | Description |
|---|---|---|
| `workload_id` | string | must match an enrolled KMS workload |
| `uses_gpu` | bool | when true, GPU evidence is required and verified |
| `issued_at` | int | unix seconds; must be within the freshness window |
| `cpu` | object | TDX-style quote: `quote_version`, `tee_type`, `tcb_version`, `td_attributes`, `mrtd`, `rtmr0`–`rtmr3`, `session_nonce` |
| `gpu` | object | optional: `device_model`, `device_id`, `driver_version`, `vbios_version`, `firmware{component: hex}`, `session_nonce` |

Success (`200`): `{ "pass": true, "score": 1.0, "key_b64": "<data key>", "binding": "<hmac>", "sources": [...] }`

Denial (`403`): `{ "pass": false, "score": 0.5, "reasons": [...], "sources": [...] }`

Malformed body (`400`): `{ "error": "..." }`

### `GET /v1/healthz`

`{ "status": "ok", "time": "..." }`

### `GET /v1/audit`

`{ "decisions": [ { "time", "workload_id", "granted", "reasons" } ] }` — newest last, capped at 200 entries.

## What this demonstrates (interview talking points)

- **Composite trust decisions.** Single-source attestation is rarely enough
  for real deployments; this shows how to combine heterogeneous evidence
  (CPU TEE + GPU TEE) into one release decision with explicit binding and
  freshness rules.
- **Policy before crypto.** Structure validation, freshness, and session
  binding are enforced before any key material is touched — the order of
  checks is itself a design decision.
- **Fail-closed key release.** The KMS only unwraps on a passing composite
  verdict; every grant *and* denial is audited with reasons.
- **Workload-aware requirements.** GPU evidence is required iff the workload
  declares `uses_gpu` — policy adapts to the workload instead of forcing a
  one-size-fits-all rule.
- **Clean interfaces.** `verifier.Verifier` is an interface, so a real
  ECDSA quote-signature verifier can replace the golden-value comparison
  without touching the combiner.

## Limitations / how I'd productionize it

- **No signature verification.** Evidence arrives as JSON and measurements
  are compared to golden values. Production would verify the TDX quote's
  ECDSA signature chain (PCK → QE) and the GPU report's signature before
  trusting any field.
- **Golden values are static.** The reference manifest is a local file;
  production would fetch TCB info / firmware allowlists from vendor
  services and pin them with signatures.
- **Mock KMS.** The master key comes from an env var and wrapped keys live
  in a file. Production: HSM/KMS-backed wrapping, per-tenant key
  isolation, and rate-limited release.
- **Audit is in-memory.** Production would ship decisions to an append-only
  log (e.g. a transparency log) for tamper evidence.
- **No mTLS / auth on the API.** Any caller can request attestation;
  production would authenticate workloads and rate-limit by identity.

## Clean-room statement

This project was built from public concepts and general engineering
practice. It contains no Intel-internal code, APIs, or non-public details;
"TDX" and "NVIDIA" appear only as the public names of the technologies whose
*shapes* of evidence the JSON model mirrors. All measurements, keys, and
golden values are fictional fixtures.

## License

MIT — see [LICENSE](LICENSE).
