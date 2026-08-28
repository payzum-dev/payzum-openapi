/**
 * Generates vectors/webhook-signatures.json — the shared test corpus that every
 * Payzum SDK verifies its webhook implementation against.
 *
 * Why this file exists: the 21 cart plugins each hand-rolled HMAC verification
 * and 20 of them read the wrong header. One corpus consumed by all SDKs makes
 * that class of divergence impossible to ship.
 *
 * The signing here mirrors the gateway exactly:
 *   - payment_ipn  lib/ipn-signing.ts        sortedStringify + HMAC-SHA-512
 *   - coinpayments lib/ipn-adapters/cp-adapter.ts  form-encoded + HMAC-SHA-512
 *   - mass_payout  src/mass-payout/ipn-adapter.ts  JSON.stringify + HMAC-SHA-256
 *
 * Output is deterministic: no clock, no randomness. Time-dependent cases carry
 * an explicit `now` so a test never depends on when it runs.
 *
 * Usage: node scripts/generate-vectors.mjs
 */
import { createHmac } from 'node:crypto'
import { writeFileSync } from 'node:fs'

const SECRET = 'payzum_test_webhook_secret_do_not_use_in_production'

/** Recursive alphabetical key sort — byte-identical to the gateway's. */
function sortedStringify(v) {
  if (v === null || typeof v !== 'object') return JSON.stringify(v)
  if (Array.isArray(v)) return '[' + v.map(sortedStringify).join(',') + ']'
  return (
    '{' +
    Object.keys(v)
      .sort()
      .map(k => JSON.stringify(k) + ':' + sortedStringify(v[k]))
      .join(',') +
    '}'
  )
}

const hmac = (alg, secret, msg) => createHmac(alg, secret).update(msg, 'utf8').digest('hex')

/** Flip one hex char so the signature stays well-formed but wrong. */
const corrupt = sig => (sig[0] === '0' ? '1' : '0') + sig.slice(1)

// ---------------------------------------------------------------- payment IPN

const EVENT_AT = 1788000000 // fixed epoch seconds; no wall clock anywhere
const ipnPayload = {
  payment_id: 'pzi_c8k2m4p6r8t0v2x4z6b8d0f2',
  payment_status: 'finished',
  price_amount: 49.99,
  price_currency: 'usd',
  pay_amount: 49.99,
  pay_currency: 'usdcmatic',
  actually_paid: 49.99,
  amount_received: 49.99,
  order_id: 'ORDER-12345',
  purchase_id: 'pzi_c8k2m4p6r8t0v2x4z6b8d0f2',
  invoice_type: 'payment',
  network: 'polygon',
  created_at: '2026-08-28T10:00:00.000Z',
  updated_at: '2026-08-28T10:04:00.000Z',
  event_id: 'pzie_9a8b7c6d5e4f3a2b1c0d9e8f',
  event_at: EVENT_AT,
}
const ipnBody = sortedStringify(ipnPayload)
const ipnSig = hmac('sha512', SECRET, ipnBody)

const stalePayload = { ...ipnPayload, event_at: EVENT_AT - 900 } // 15 min old
const staleBody = sortedStringify(stalePayload)

const futurePayload = { ...ipnPayload, event_at: EVENT_AT + 900 } // 15 min ahead
const futureBody = sortedStringify(futurePayload)

// ---------------------------------------------------------------- CoinPayments

const cpFields = {
  amount1: '49.99000000',
  amount2: '49.99000000',
  currency1: 'USD',
  currency2: 'USDC.POLY',
  fee: '0.00000000',
  ipn_id: 'cp_1a2b3c4d5e6f7a8b9c0d1e2f',
  ipn_mode: 'hmac',
  ipn_type: 'api',
  ipn_version: '1.0',
  merchant: 'pzm_4f3e2d1c0b9a8f7e6d5c4b3a',
  received_amount: '49.99000000',
  received_confirms: '12',
  status: '100',
  status_text: 'Payment complete',
  txn_id: 'cptx_7e6d5c4b3a2f1e0d9c8b7a6f',
}
// Sorted keys, then URL-encoded — matches buildCpIpnBody.
const cpBody = new URLSearchParams(
  Object.keys(cpFields)
    .sort()
    .map(k => [k, cpFields[k]]),
).toString()
const cpSig = hmac('sha512', SECRET, cpBody)

// ---------------------------------------------------------------- mass payout

const mpPayload = {
  eventType: 'mass_payout.batch_confirmed',
  eventId: 'pzwe_2b3c4d5e6f7a8b9c0d1e2f3a',
  eventAt: EVENT_AT,
  order: {
    id: 'mpo_5c4b3a2f1e0d9c8b7a6f5e4d',
    chain: 'bitcoin',
    mode: 'mainnet',
    status: 'executing',
    recipientCount: 250,
  },
}
// NOTE: plain JSON.stringify here, NOT sorted — the gateway differs between
// the two families and a verifier must sign over raw bytes either way.
const mpBody = JSON.stringify(mpPayload)
const mpSig = hmac('sha256', SECRET, mpBody)

// ---------------------------------------------------------------- corpus

const doc = {
  version: 1,
  description:
    'Shared webhook-signature test vectors for all Payzum SDKs. Every case is ' +
    'computed from the gateway signing algorithms; none are hand-written. ' +
    'Bodies are exact UTF-8 strings — sign and verify those bytes verbatim.',
  secret: SECRET,
  replay_window_seconds: 600,
  schemes: {
    payment_ipn: {
      algorithm: 'HMAC-SHA-512',
      encoding: 'hex-lowercase',
      header: 'x-nowpayments-sig',
      event_id_header: 'x-payzum-event-id',
      content_type: 'application/json',
      body_construction: 'recursive alphabetical key sort, then JSON serialize',
      timestamp_field: 'event_at',
      dedup_field: 'event_id',
      notes:
        'Header name comes from the NowPayments-compatible dialect. It is FIXED. ' +
        'Do not make it configurable and do not reuse X-Payzum-Signature here.',
      cases: [
        { name: 'valid', body: ipnBody, signature: ipnSig, valid: true },
        {
          name: 'valid_uppercase_hex',
          body: ipnBody,
          signature: ipnSig.toUpperCase(),
          valid: true,
          why: 'Hex is case-insensitive. Decode to bytes (or lowercase) before comparing.',
        },
        { name: 'bad_signature', body: ipnBody, signature: corrupt(ipnSig), valid: false },
        {
          name: 'tampered_body',
          body: ipnBody.replace('"actually_paid":49.99', '"actually_paid":4999'),
          signature: ipnSig,
          valid: false,
          why: 'Amount inflated after signing — must not verify.',
        },
        {
          name: 'wrong_algorithm_sha256',
          body: ipnBody,
          signature: hmac('sha256', SECRET, ipnBody),
          valid: false,
          why: 'Mass-payout algorithm applied to a payment IPN.',
        },
        { name: 'empty_signature', body: ipnBody, signature: '', valid: false },
        {
          name: 'truncated_signature',
          body: ipnBody,
          signature: ipnSig.slice(0, 64),
          valid: false,
          why: 'Compare lengths before any constant-time compare, or it throws.',
        },
        {
          name: 'wrong_secret',
          body: ipnBody,
          signature: hmac('sha512', 'some_other_secret', ipnBody),
          valid: false,
        },
      ],
      replay_cases: [
        { name: 'fresh', body: ipnBody, signature: ipnSig, now: EVENT_AT + 30, accept: true },
        {
          name: 'stale_beyond_window',
          body: staleBody,
          signature: hmac('sha512', SECRET, staleBody),
          now: EVENT_AT,
          accept: false,
          why: 'event_at is 900s old, window is 600s. Signature is VALID; reject on age.',
        },
        {
          name: 'future_beyond_skew',
          body: futureBody,
          signature: hmac('sha512', SECRET, futureBody),
          now: EVENT_AT,
          accept: false,
          why: 'Clock skew guard: reject timestamps far in the future too.',
        },
      ],
      dedup_case: {
        event_id: ipnPayload.event_id,
        why: 'Retries reuse the same event_id. Second delivery must be a no-op, not a second fulfilment.',
      },
    },

    coinpayments_ipn: {
      algorithm: 'HMAC-SHA-512',
      encoding: 'hex-lowercase',
      header: 'HMAC',
      content_type: 'application/x-www-form-urlencoded',
      body_construction: 'alphabetical key sort, then form-urlencode',
      timestamp_field: null,
      dedup_field: 'ipn_id',
      notes:
        'Delivered to merchants issued CoinPayments keys. THE PAYLOAD CARRIES NO ' +
        'TIMESTAMP, so no replay window is possible — dedup on ipn_id is the only ' +
        'defence. No x-payzum-event-id header is sent for this shape.',
      cases: [
        { name: 'valid', body: cpBody, signature: cpSig, valid: true },
        { name: 'bad_signature', body: cpBody, signature: corrupt(cpSig), valid: false },
        {
          name: 'tampered_body',
          body: cpBody.replace('status=100', 'status=1'),
          signature: cpSig,
          valid: false,
        },
        { name: 'empty_signature', body: cpBody, signature: '', valid: false },
      ],
      replay_cases: [],
      dedup_case: {
        ipn_id: cpFields.ipn_id,
        why: 'Only defence available for this shape — there is no timestamp to age out.',
      },
    },

    mass_payout: {
      algorithm: 'HMAC-SHA-256',
      encoding: 'hex-lowercase',
      header: 'X-Payzum-Signature',
      event_id_header: 'X-Payzum-Event-Id',
      content_type: 'application/json',
      body_construction: 'JSON.stringify as-is — NOT key-sorted, unlike payment_ipn',
      timestamp_field: 'eventAt',
      dedup_field: 'eventId',
      notes:
        'camelCase fields, and SHA-256 rather than SHA-512. Event ids are prefixed pzwe_.',
      cases: [
        { name: 'valid', body: mpBody, signature: mpSig, valid: true },
        { name: 'bad_signature', body: mpBody, signature: corrupt(mpSig), valid: false },
        {
          name: 'wrong_algorithm_sha512',
          body: mpBody,
          signature: hmac('sha512', SECRET, mpBody),
          valid: false,
          why: 'Payment-IPN algorithm applied to a mass-payout webhook.',
        },
        {
          name: 'tampered_body',
          body: mpBody.replace('"recipientCount":250', '"recipientCount":1'),
          signature: mpSig,
          valid: false,
        },
        { name: 'empty_signature', body: mpBody, signature: '', valid: false },
      ],
      replay_cases: [
        { name: 'fresh', body: mpBody, signature: mpSig, now: EVENT_AT + 30, accept: true },
      ],
      dedup_case: {
        eventId: mpPayload.eventId,
        why: 'Stable across retries — dedupe on it.',
      },
    },
  },

  cross_scheme_confusion: {
    why:
      'The bug this corpus exists to prevent: 20 of 21 cart plugins read ' +
      'x-payzum-signature (the MASS PAYOUT header) for a payment IPN. Every SDK ' +
      'must fail these.',
    cases: [
      {
        name: 'mass_payout_header_on_payment_ipn',
        scheme: 'payment_ipn',
        header_used: 'X-Payzum-Signature',
        expect: 'header not found — verification must fail closed, never skip',
      },
      {
        name: 'payment_ipn_verifier_on_mass_payout_body',
        body: mpBody,
        signature: mpSig,
        verify_as: 'payment_ipn',
        valid: false,
        why: 'SHA-512 verifier against a SHA-256 signature.',
      },
    ],
  },
}

const out = new URL('../vectors/webhook-signatures.json', import.meta.url)
writeFileSync(out, JSON.stringify(doc, null, 2) + '\n')

const n =
  Object.values(doc.schemes).reduce(
    (a, s) => a + s.cases.length + s.replay_cases.length,
    0,
  ) + doc.cross_scheme_confusion.cases.length
console.log(`wrote ${out.pathname}`)
console.log(`${Object.keys(doc.schemes).length} schemes, ${n} cases`)
