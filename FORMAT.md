# Sigilbase evidence bundle format

This document is the normative specification of the `sigilbase-evidence`
bundle format, kept in lockstep with the application docs page
(`docs/evidence-bundles.md`, published at `/docs/evidence-bundles`). The
docs page is the readable version; where wording differs, this file and
the verifier's behaviour are authoritative. Anything not specified is not
part of the format; consumers must ignore unknown fields and files rather
than reject them.

The current format identifier is **`sigilbase-evidence/1.4`**.

## Compatibility

The verifier version (`VERIFIER_VERSION` in `verify.php`, semver) and the
bundle format version are distinct:

| Verifier | Formats verified | Notes |
| --- | --- | --- |
| 1.0.x | `sigilbase-evidence/1` | In-app only; never published |
| 1.1.x | `sigilbase-evidence/1`, `sigilbase-evidence/1.1` | Adds anchor validation, `--skip-anchors`, `--consistency` |
| 1.2.x | `sigilbase-evidence/1`, `sigilbase-evidence/1.1`, `sigilbase-evidence/1.2` | Adds `payload_state` and the redactions manifest; fails undeclared payload absence |
| 1.3.x | `sigilbase-evidence/1`, `sigilbase-evidence/1.1`, `sigilbase-evidence/1.2`, `sigilbase-evidence/1.3` | Reports qualified-TSA metadata (informational, never part of the verdict); checks Certificates of Evidence against their manifest hashes |
| 1.4.x | `sigilbase-evidence/1`, `sigilbase-evidence/1.1`, `sigilbase-evidence/1.2`, `sigilbase-evidence/1.3`, `sigilbase-evidence/1.4` | Cross-checks the SigilSign blocks (`documents.json`, `signatures.json`, `links.json`) against the events; a contradiction fails, legal-effect claims never influence the verdict |

Format 1.1 is strictly additive over format 1: it adds `anchors.json`
(always present, possibly an empty list) and `consistency.json` (present
only when the bundle starts at sequence 1).

Format 1.2 is strictly additive over format 1.1: it adds a per-event
`payload_state` field in `events.ndjson` and the `redactions.json`
manifest (always present, possibly an empty list). Nothing about the
hashing changes — a redacted event's entry hash still commits to its
preserved `payload_hash`, so chains, Merkle roots, signatures, anchors,
and consistency proofs are computed exactly as in earlier formats.

Format 1.3 is strictly additive over format 1.2: anchor records gain
informational qualified-TSA metadata (`provider_name`, `jurisdiction`,
`qualified`, `signer_serial`), and Certificates of Evidence issued over
records inside the exported range may travel under `certificates/`, each
listed in the manifest's `certificates` array with its SHA-256. Nothing
about the hashing or verification mathematics changes.

Format 1.4 is strictly additive over format 1.3: it adds three optional
files — `documents.json` (documents by hash and metadata),
`signatures.json` (signature records with per-signer facts including the
sha256 of the exact version each signer viewed and signed), and
`links.json` (document ↔ event associations) — each written only when the
exported range touches the corresponding facts. All three are
informational-but-verifiable: their statements are cross-checked against
the events themselves and a contradiction fails verification, while
unknown fields — including any claim about legal effect or validity —
are ignored and can never influence the verdict. Format 1.4 additionally
reserves `witness.json` (cross-tenant witness proofs: per-checkpoint
inclusion proofs against a signed tree head of shape `tree_size`,
`root_hash`, `period`, `timestamp`, `previous_sth_hash`, `signature`)
and `attestations.json` (the continuous-verification attestation chain:
records of shape `date`, `streams_verified`, `entries_checked`, `result`,
`chain_heads_digest`, `previous_attestation_hash`, `signature`). Neither
is emitted yet; consumers must ignore them until a verifier release
verifies them. Nothing about the hashing or verification mathematics
changes.

## Bundle contents

A bundle is a zip archive (or the equivalent extracted directory):

| File | Purpose | Since |
| --- | --- | --- |
| `manifest.json` | Format id, stream identity, exported range, signing keys | 1 |
| `events.ndjson` | The events, one canonical JSON object per line | 1 |
| `checkpoints.json` | The signed checkpoints covering the range | 1 |
| `anchors.json` | RFC 3161 timestamp tokens over checkpoint hashes | 1.1 |
| `consistency.json` | Cumulative RFC 6962 tree states per checkpoint | 1.1 |
| `redactions.json` | Declares every event in the range whose payload was redacted | 1.2 |
| `certificates/*.pdf` | Certificates of Evidence covering records in the range, hashes in the manifest | 1.3 |
| `documents.json` | Documents of the stream by hash and metadata (optional; present when the range covers publications) | 1.4 |
| `signatures.json` | Signature records with per-signer facts and the viewed/signed version hashes (optional) | 1.4 |
| `links.json` | Document ↔ event links with their ledgered fact sequences (optional) | 1.4 |
| `witness.json` | Reserved: cross-tenant witness proofs (specified, not yet emitted) | 1.4 |
| `attestations.json` | Reserved: continuous-verification attestation chain (specified, not yet emitted) | 1.4 |
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
- **Qualified anchor metadata** (1.3): anchor records may carry
  `provider_name` (string), `jurisdiction` (string or null), `qualified`
  (bool or null — the provider's configured status *at anchor time*), and
  `signer_serial` (uppercase hex of the token signer certificate's serial,
  or null). All four are informational statements by the exporting
  instance. Verifiers report them and must never let them influence the
  verdict: a token claimed qualified that fails the cryptographic checks
  fails, exactly as any other token does.
- **Certificate of Evidence** (1.3): a PDF issued by the exporting
  instance summarising what the mathematics prove about a record or range
  within the bundle. Each travels under `certificates/` and appears in
  the manifest's `certificates` array as `id`, `issued_at` (RFC 3339),
  `scope` (object), `file` (path under `certificates/`), and `sha256`
  (hex of the file bytes). Certificates are documents about the evidence,
  not evidence: verifiers check each listed file exists and matches its
  hash (a listed-but-missing or mismatching file is a failure — evidence
  with pieces deleted must never pass) and nothing more.
- **SigilSign blocks** (1.4): `documents.json` holds
  `{"documents": [...]}` — per document `slug`, `title`, `category`,
  optional `resource`, and `versions` of `version`, `sha256` (hex of the
  exact file bytes), `size_bytes`, `origin` (`uploaded`, `generated`, or
  `countersigned`), `published_at` (RFC 3339), `published_sequence`.
  `signatures.json` holds `{"signatures": [...]}` — per record `id`,
  `document` (`slug`, `version`, `sha256`), `order` (`parallel` |
  `sequential`), `status` (`open` | `completed` | `voided`), optional
  `completed_at`, `event_sequences`, and `signers` of `position`, `name`,
  `email`, optional `role`, `status`, optional `viewed_sha256`,
  `signed_at`, `intent_statement`, `signature_sha256` (hex of the
  signature-mark image bytes), `email_confirmed`. `links.json` holds
  `{"links": [...]}` — per link `sha256` (the linked artefact's hash),
  `source_type`, `target` (`type`, `reference`, and the type's fields),
  `linked_sequence`, optional `unlinked_sequence`, `active`. Verifiers
  must cross-check every stated hash and sequence against the events —
  a version's `published_sequence` must be its `document.published`
  event carrying the same `sha256`; a signer's `signature.viewed` and
  `signature.signed` events must reference the same `sha256`, which is
  the document's; a link's sequences must resolve to
  `document.linked`/`document.unlinked` events carrying the same
  `sha256` — and fail on contradiction. Unknown fields, including any
  claim about legal effect or validity, are ignored and must never
  influence the verdict. These blocks state what a tenant's workspace
  recorded; signatures are simple electronic signatures and the format
  asserts nothing about their effect in any jurisdiction.
- **Redacted event** (1.2): an event whose stored payload was destroyed
  by the exporting tenant after ingestion (hash-preserving redaction). In
  `events.ndjson` it carries `payload: null` and
  `payload_state: "redacted"`; every other field — including
  `payload_hash` — is exactly as written at ingestion. `payload_state` is
  `"present"` for all other events and may be omitted in pre-1.2 bundles.
  Each redacted event must have an entry in `redactions.json`:
  `sequence`, `redacted_at` (RFC 3339), and `declared_by` — a reference
  (`stream` slug, `sequence`, `entry_hash`) to the `payload.redacted`
  ledger event recording the act, which may live outside the exported
  range (it appends to the same stream, or to the tenant's
  `sigilbase-system` stream when the redacted stream was archived).
  `declared_by` is advisory context; the acceptance rule is the triple
  agreement below.

A redacted event verifies through its preserved `payload_hash`: the entry
preimage commits to the hash rather than the payload bytes, so entry
hashes, the chain, Merkle roots, signatures, anchors, and consistency
proofs all recompute without the payload. What cannot be recomputed is
the payload hash itself — the verifier therefore reports each redaction
plainly instead of silently trusting it, and the preserved hash retains
evidential value: a purported original that resurfaces can be checked
against it.

An absent payload is accepted **only** when all three signals agree:
`payload_state` is `"redacted"`, `payload` is `null`, and
`redactions.json` declares the sequence. Any other combination — an
absent payload without the state, the state with a payload still present,
a declaration for a present payload, or a redacted event missing from the
manifest — fails verification. Absence must be declared, never implied.

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
`tree_size`/`root` pair. Redacted events are reported one line each
(sequence and redaction date) and counted in the summary; they are never
silent. The verifier makes no network calls and requires PHP ≥ 8.2 with
ext-sodium (ext-zip for `.zip` input, ext-openssl for anchors; nothing
else, not even mbstring).
