# payzum-openapi

The machine-readable contract every official Payzum SDK is built and validated
against, plus the shared webhook-signature test corpus.

Two artefacts live here:

| Path | What it is |
|---|---|
| `openapi/payzum-v1.yaml` | OpenAPI 3.1 for the `/v1` API — 32 paths, extracted from the gateway handler code, not from prose |
| `vectors/webhook-signatures.json` | Test corpus for the three webhook signature schemes, consumed by all SDKs |

## Why the vectors exist

Payzum ships 21 shopping-cart plugins. Each one hand-rolled its own HMAC
verification, and **20 of the 21 read the wrong header** — `x-payzum-signature`,
which is the *mass payout* header, for a *payment* IPN. The signature never
verifies, deliveries get a 401, the gateway retries five times and dead-letters,
and the order is silently never fulfilled.

One error, copied twenty times, because twenty implementations had nothing to
agree with.

Every SDK now verifies against this single corpus. Divergence stops being a
thing that can ship.

## The three schemes

None of them is interchangeable.

| Scheme | Algorithm | Header | Body | Replay defence |
|---|---|---|---|---|
| `payment_ipn` | HMAC-SHA-512 | `x-nowpayments-sig` | key-sorted JSON | `event_at` + 10 min window, dedup on `event_id` |
| `coinpayments_ipn` | HMAC-SHA-512 | `HMAC` | form-urlencoded | **no timestamp exists** — dedup on `ipn_id` only |
| `mass_payout` | HMAC-SHA-256 | `X-Payzum-Signature` | `JSON.stringify` as-is, *not* sorted | `eventAt` + window, dedup on `eventId` |

The payment IPN header is named after Payzum's NowPayments-compatible dialect,
which lets an existing NowPayments integration point at Payzum without code
changes. It is **fixed**. Do not make it configurable — a setting is an
invitation to fill it with the wrong value, and the failure mode is silent.

## Using the corpus

```json
{
  "secret": "…",
  "replay_window_seconds": 600,
  "schemes": {
    "payment_ipn": {
      "algorithm": "HMAC-SHA-512",
      "header": "x-nowpayments-sig",
      "cases": [ { "name": "valid", "body": "…", "signature": "…", "valid": true } ],
      "replay_cases": [ { "name": "stale_beyond_window", "now": 1788000000, "accept": false } ]
    }
  },
  "cross_scheme_confusion": { "cases": [ … ] }
}
```

Bodies are exact UTF-8 strings. Sign and verify **those bytes verbatim** — never
re-parse and re-serialize, or key ordering will break the signature.

Three case families, and an SDK must pass all three:

- **`cases`** — signature correctness. Includes uppercase hex (must verify, hex
  is case-insensitive), truncated signatures (compare lengths *before* any
  constant-time compare or it throws), and wrong-algorithm signatures.
- **`replay_cases`** — carry an explicit `now` so a test never depends on the
  wall clock. A stale event has a **valid signature** and must still be rejected,
  on age.
- **`cross_scheme_confusion`** — reproduces the plugin bug directly. An SDK that
  passes everything else and fails these has the exact defect this repo exists
  to prevent.

## Regenerating and checking

```bash
node scripts/generate-vectors.mjs   # deterministic: no clock, no randomness
python3 scripts/verify_vectors.py   # independent re-check, exits non-zero on disagreement
```

The verifier is written in a different language from the generator on purpose.
If two independent implementations agree on every case, the corpus is
language-neutral. It currently reports 22/22, and a third spot-check in PHP
agrees on all 17 signature cases.

## Keeping the OpenAPI in sync

`openapi/payzum-v1.yaml` is a copy. The source of truth is
`workers/payzum/gateway/openapi/payzum-v1.yaml` in the `saas-core` repo, where a
contract test suite runs it against the live API on every build.

```bash
./scripts/sync-openapi.sh /path/to/saas-core/cloudflare-saas
```

Never hand-edit the copy. If it drifts, the SDKs generate types for an API that
does not exist — which is the failure this whole line of work started from.

## License

MIT — see [LICENSE](LICENSE).
