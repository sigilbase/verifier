# Sigilbase evidence bundle format

This document is the normative specification of the `sigilbase-evidence`
bundle format, kept in lockstep with the application docs page
(`docs/evidence-bundles.md`, published at `/docs/evidence-bundles`). The
docs page is the readable version; where wording differs, this file and
the verifier's behaviour are authoritative. Anything not specified is not
part of the format; consumers must ignore unknown fields and files rather
than reject them.

The current format identifier is **`sigilbase-evidence/1.1`**.

## Compatibility

The verifier version (`VERIFIER_VERSION` in `verify.php`, semver) and the
bundle format version are distinct:

| Verifier | Formats verified | Notes |
| --- | --- | --- |
| 1.0.x | `sigilbase-evidence/1` | In-app only; never published |
| 1.1.x | `sigilbase-evidence/1`, `sigilbase-evidence/1.1` | Adds anchor validation, `--skip-anchors`, `--consistency` |

Format 1.1 is strictly additive over format 1: it adds `anchors.json`
(always present, possibly an empty list) and `consistency.json` (present
only when the bundle starts at sequence 1).

## Bundle contents

A bundle is a zip archive (or the equivalent extracted directory):

| File | Purpose | Since |
| --- | --- | --- |
| `manifest.json` | Format id, stream identity, exported range, signing keys | 1 |
| `events.ndjson` | The events, one canonical JSON object per line | 1 |
| `checkpoints.json` | The signed checkpoints covering the range | 1 |
| `anchors.json` | RFC 3161 timestamp tokens over checkpoint hashes | 1.1 |
| `consistency.json` | Cumulative RFC 6962 tree states per checkpoint | 1.1 |
| `README.txt` | Plain-language instructions for the bundle holder | 1 |
| `verify.php` | This verifier, copied into every bundle | 1 |

## Cryptographic definitions

- **Canonical JSON** is RFC 8785 (JCS) restricted to integers: floats are
  rejected, integers must satisfy |n| ≤ 2^53−1, object keys sort by UTF-16
  code units, and control characters below U+0020 are escaped.
- **Entry hash**: SHA-256 over the canonical JSON object with keys `v` (1),
  `stream` (stream UUID), `seq`, `occurred_at`, `received_at`, `actor`,
  `action`, `resource`, `payload_hash`, `prev`. `payload_hash` is SHA-256
  of the payload's canonical JSON. `prev` is the previous entry hash, 64
  zeros for sequence 1. All hashes are lowercase hex.
- **Merkle tree**: RFC 6962. `leaf = SHA-256(0x00 || data)`,
  `node = SHA-256(0x01 || left || right)`; for n > 1 leaves the split is
  at the largest power of two smaller than n. Leaves are the raw 32-byte
  entry hashes.
- **Checkpoint hash**: SHA-256 over canonical JSON with keys `v` (1),
  `stream`, `from`, `to`, `root` (the batch Merkle root over entries
  `from..to`), `prev_checkpoint`, `created_at` (RFC 3339 UTC,
  microseconds).
- **Checkpoint signature**: Ed25519 over the raw 32 bytes of the
  checkpoint hash. Trusted public keys are listed in the manifest.
- **Anchor token** (1.1): a DER RFC 3161 `TimeStampToken` (RFC 5652 CMS
  `SignedData` over a `TSTInfo`) whose message imprint is SHA-256 over the
  raw 32 bytes of the checkpoint hash. `token` is base64 of the DER;
  `token_hash` is SHA-256 hex of the DER; `ca_pem`, when present, is the
  TSA chain as configured by the exporting instance (advisory — obtain the
  TSA root independently for full trust).
- **Cumulative tree state** (1.1): the RFC 6962 tree over entry hashes
  `1..n`; a checkpoint's state has `tree_size = sequence_to`. Consistency
  proofs between states follow RFC 6962 §2.1.2 (generation) and RFC 9162
  §2.1.4.2 (verification).

Field-by-field tables and worked examples live in the docs page; the
in-repo test corpus (`tests/Feature/Verifier/`) is the executable
specification of every failure mode.

## Verifier behaviour

Exit codes: `0` = every check passed; `1` = the bundle does not verify,
including bundles with required files missing (evidence with pieces
deleted must never pass); `2` = usage or format error (bad arguments, a
path that does not exist, or an unknown format id — nothing was verified
either way).

Flags: `--json` emits one machine-readable result document on stdout;
`--quiet` produces no output at all (the exit code is the whole answer);
`--print-hashes` reports the SHA-256 of the verifier file and of the
bundle file(s) so a run can be recorded precisely; `--skip-anchors` skips
anchor validation. Anchors are validated when PHP's openssl extension is
available; when it is not, they are reported as present-but-unverified and
this is never a failure by itself. `--consistency` proves one export
extends another, from two bundles or from a bundle plus a recorded
`tree_size`/`root` pair. The verifier makes no network calls and requires
PHP ≥ 8.2 with ext-sodium (ext-zip for `.zip` input, ext-openssl for
anchors; nothing else, not even mbstring).
