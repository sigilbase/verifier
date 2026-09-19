# Sigilbase evidence bundle format

This document is the normative specification of the `sigilbase-evidence`
bundle format, kept in lockstep with the application docs page
(`docs/evidence-bundles.md`, published at `/docs/evidence-bundles`). The
docs page is the readable version; where wording differs, this file and
the verifier's behaviour are authoritative. Anything not specified is not
part of the format; consumers must ignore unknown fields and files rather
than reject them.

The current format identifier is **`sigilbase-evidence/1.5`**.

## Compatibility

The verifier version (`VERIFIER_VERSION` in `verify.php`, semver) and the
bundle format version are distinct:

| Verifier | Formats verified | Notes |
| --- | --- | --- |
| 1.0.x | `sigilbase-evidence/1` | In-app only; never published |
| 1.1.x | `sigilbase-evidence/1`, `sigilbase-evidence/1.1` | Adds anchor validation, `--skip-anchors`, `--consistency` |
| 1.2.x | `sigilbase-evidence/1`, `sigilbase-evidence/1.1`, `sigilbase-evidence/1.2` | Adds `payload_state` and the redactions manifest; fails undeclared payload absence |
| 1.3.x | `sigilbase-evidence/1`, `sigilbase-evidence/1.1`, `sigilbase-evidence/1.2`, `sigilbase-evidence/1.3` | Reports qualified-TSA metadata (informational, never part of the verdict); checks Certificates of Evidence against their manifest hashes |
| 1.4.x | `sigilbase-evidence/1`, `sigilbase-evidence/1.1`, `sigilbase-evidence/1.2`, `sigilbase-evidence/1.3`, `sigilbase-evidence/1.4` | Cross-checks the SigilSign blocks (`documents.json`, `signatures.json`, `links.json`) against the events; a contradiction fails, legal-effect claims never influence the verdict. 1.4.1 holds every issuer in an anchor token's certificate chain to CA rules (see *Anchor token* below); a chain through a non-CA certificate now fails. 1.4.2 holds every checkpoint to its signing key's active window (see *Checkpoint signature* below); a checkpoint dated after its key's `retired_at`, or before its `created_at`, now fails even with a verifying signature |
| 1.5.x | `sigilbase-evidence/1` through `sigilbase-evidence/1.5` | Reports five results (content integrity, signing identity, timestamps, scope, redactions) and four exit codes (0 pass, 1 fail, 2 error, 3 unconfirmed). Carries a trusted signing key set and timestamp trust roots, so a bundle signed with a key the verifier does not know is UNCONFIRMED rather than PASS; `--keys` and `--tsa-roots` replace either set. An absent payload is accepted only against an authenticated declaration in the bundle that names that event, so a bundle below 1.5 carrying an absent payload now fails and must be exported again. Reads `events.ndjson` a line at a time, so bundle size no longer bounds who can verify |
| 1.6.x | `sigilbase-evidence/1` through `sigilbase-evidence/1.5` | Adds a second implementation, `sigilbase-verify` (Go), released under the same tag and held to the same exit code and results as `verify.php` on every corpus fixture; specifies parsing, Ed25519 acceptance and the accepted token algorithms (see *Parsing* and *Ed25519 acceptance* below); carries the production timestamp trust roots, so anchored production bundles pass by default and a bundle anchored by an authority the verifier does not carry fails `timestamps` unless `--tsa-roots` names it; reports `verifier_name` in the `--json` document, described by `result.schema.json`; and no longer stops on a hostile field type or date, reporting a failure of that record instead |

Format 1.1 is strictly additive over format 1: it adds `anchors.json`
(always present, possibly an empty list) and `consistency.json` (present
only when the bundle starts at sequence 1).

Format 1.2 is strictly additive over format 1.1: it adds a per-event
`payload_state` field in `events.ndjson` and the `redactions.json`
manifest (always present, possibly an empty list). Nothing about the
hashing changes - a redacted event's entry hash still commits to its
preserved `payload_hash`, so chains, Merkle roots, signatures, anchors,
and consistency proofs are computed exactly as in earlier formats.

Format 1.3 is strictly additive over format 1.2: anchor records gain
informational qualified-TSA metadata (`provider_name`, `jurisdiction`,
`qualified`, `signer_serial`), and Certificates of Evidence issued over
records inside the exported range may travel under `certificates/`, each
listed in the manifest's `certificates` array with its SHA-256. Nothing
about the hashing or verification mathematics changes.

Format 1.4 is strictly additive over format 1.3: it adds three optional
files - `documents.json` (documents by hash and metadata),
`signatures.json` (signature records with per-signer facts including the
sha256 of the exact version each signer viewed and signed), and
`links.json` (document ↔ event associations) - each written only when the
exported range touches the corresponding facts. All three are
informational-but-verifiable: their statements are cross-checked against
the events themselves and a contradiction fails verification, while
unknown fields - including any claim about legal effect or validity -
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

Format 1.5 is strictly additive over format 1.4: it adds
`declarations.ndjson` (full entry records for every declaration covering
an absent payload in the exported range, including any supplementary
declaration and the original it references) and
`declaration_proofs.json` (for declarations outside the exported range:
an audit path to the checkpoint that sealed each one, and that
checkpoint, marked `outside_range`). Absent-payload event lines also
carry `absence`, either `redacted` or `erased`, saying which ceremony
destroyed the payload.

`redactions.json` remains, as an index and never as authority: an index
is written by the exporter and cannot be checked against anything, so it
informs a reader and never decides a verdict. An absence is accepted
only against a declaration whose entry hash recomputes, whose payload
matches its payload hash, whose action matches the kind of absence,
whose targets name that exact stream and sequence, and which was sealed
in a checkpoint whose signature verifies inside its key's trusted
window. A declaration in the same stream must also come after the event
it destroyed. Nothing about the hashing mathematics changes.

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
| `declarations.ndjson` | The declarations covering every absent payload in the range, as full entry records | 1.5 |
| `declaration_proofs.json` | Audit paths and sealing checkpoints for declarations outside the range | 1.5 |
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
  checkpoint hash. Trusted public keys are listed in the manifest, each
  with its active window: `created_at` (RFC 3339) and `retired_at` (RFC
  3339, or null while the key is active). A signature is authoritative
  only for checkpoints sealed inside that window: the checkpoint's
  `created_at` - part of the signed preimage - must not be before the
  key's `created_at` nor after its `retired_at`, compared as exact
  instants. A checkpoint outside its key's window fails even though its
  signature verifies, because a retired key vouches for nothing sealed
  after its retirement and no key vouches for anything sealed before it
  existed. A window field absent from the manifest leaves that bound
  unchecked; a present but unparseable one fails.
- **Anchor token** (1.1): a DER RFC 3161 `TimeStampToken` (RFC 5652 CMS
  `SignedData` over a `TSTInfo`) whose message imprint is SHA-256 over the
  raw 32 bytes of the checkpoint hash. `token` is base64 of the DER;
  `token_hash` is SHA-256 hex of the DER; `ca_pem`, when present, is the
  TSA chain as configured by the exporting instance (advisory - obtain the
  TSA root independently for full trust). A token validates when its
  imprint is SHA-256 of the checkpoint hash, its signed `messageDigest`
  matches the `TSTInfo`, its CMS signature verifies against the signer
  certificate embedded in the token, and that signer carries the
  timestamping extended key usage (1.3.6.1.5.5.7.3.8) and was valid at
  `genTime`. When a CA is available, the signer must additionally chain to
  a self-signed root present in the CA (intermediates may come from the
  token; a root found only inside the token never counts), and every
  issuer on that path - intermediates and root alike - must be a CA that
  was valid at `genTime`: `basicConstraints` present with `cA` TRUE (an
  absent extension counts as FALSE), `keyCertSign` set when a `keyUsage`
  extension is present, and no more intermediates beneath it than its
  `pathLenConstraint` allows. Without the issuer rules, an ordinary
  end-entity certificate under a trusted root could issue a "timestamping"
  signer whose every signature verifies.
- **Cumulative tree state** (1.1): the RFC 6962 tree over entry hashes
  `1..n`; a checkpoint's state has `tree_size = sequence_to`. Consistency
  proofs between states follow RFC 6962 §2.1.2 (generation) and RFC 9162
  §2.1.4.2 (verification).
- **Qualified anchor metadata** (1.3): anchor records may carry
  `provider_name` (string), `jurisdiction` (string or null), `qualified`
  (bool or null - the provider's configured status *at anchor time*), and
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
  hash (a listed-but-missing or mismatching file is a failure - evidence
  with pieces deleted must never pass) and nothing more.
- **SigilSign blocks** (1.4): `documents.json` holds
  `{"documents": [...]}` - per document `slug`, `title`, `category`,
  optional `resource`, and `versions` of `version`, `sha256` (hex of the
  exact file bytes), `size_bytes`, `origin` (`uploaded`, `generated`, or
  `countersigned`), `published_at` (RFC 3339), `published_sequence`.
  `signatures.json` holds `{"signatures": [...]}` - per record `id`,
  `document` (`slug`, `version`, `sha256`), `order` (`parallel` |
  `sequential`), `status` (`open` | `completed` | `voided`), optional
  `completed_at`, `event_sequences`, and `signers` of `position`, `name`,
  `email`, optional `role`, `status`, optional `viewed_sha256`,
  `signed_at`, `intent_statement`, `signature_sha256` (hex of the
  signature-mark image bytes), `email_confirmed`. `links.json` holds
  `{"links": [...]}` - per link `sha256` (the linked artefact's hash),
  `source_type`, `target` (`type`, `reference`, and the type's fields),
  `linked_sequence`, optional `unlinked_sequence`, `active`. Verifiers
  must cross-check every stated hash and sequence against the events -
  a version's `published_sequence` must be its `document.published`
  event carrying the same `sha256`; a signer's `signature.viewed` and
  `signature.signed` events must reference the same `sha256`, which is
  the document's; a link's sequences must resolve to
  `document.linked`/`document.unlinked` events carrying the same
  `sha256` - and fail on contradiction. Unknown fields, including any
  claim about legal effect or validity, are ignored and must never
  influence the verdict. These blocks state what a tenant's workspace
  recorded; signatures are simple electronic signatures and the format
  asserts nothing about their effect in any jurisdiction.
- **Redacted event** (1.2): an event whose stored payload was destroyed
  by the exporting tenant after ingestion (hash-preserving redaction). In
  `events.ndjson` it carries `payload: null` and
  `payload_state: "redacted"`; every other field - including
  `payload_hash` - is exactly as written at ingestion. `payload_state` is
  `"present"` for all other events and may be omitted in pre-1.2 bundles.
  Each redacted event must have an entry in `redactions.json`:
  `sequence`, `redacted_at` (RFC 3339), and `declared_by` - a reference
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
the payload hash itself - the verifier therefore reports each redaction
plainly instead of silently trusting it, and the preserved hash retains
evidential value: a purported original that resurfaces can be checked
against it.

An absent payload is accepted **only** when all three signals agree:
`payload_state` is `"redacted"`, `payload` is `null`, and
`redactions.json` declares the sequence. Any other combination - an
absent payload without the state, the state with a payload still present,
a declaration for a present payload, or a redacted event missing from the
manifest - fails verification. Absence must be declared, never implied.

Field-by-field tables and worked examples live in the docs page. The
conformance corpus (`corpus/`, with its expectations in
`corpus/expected.json` and the hostile fixtures in `corpus/hostile/`) and
the golden vectors (`vectors/vectors.json`) are the executable
specification: every failure mode, every parsing rule and every
acceptance rule below is pinned by one of them, and both implementations
are held to them in the release pipeline.

## Verifier behaviour

Two implementations release under the same version number from 1.6.0:
`verify.php`, a single dependency-free PHP file in this repository, and
`sigilbase-verify`, a static Go binary from
[github.com/sigilbase/verifier-go](https://github.com/sigilbase/verifier-go),
which mirrors this repository's corpus, vectors, keys and schema. Neither
is the reference for the other. This document, `result.schema.json`,
`vectors/vectors.json` and `corpus/expected.json` decide what is correct,
both implementations conform to them, and the release pipelines of both
repositories hold the two to the same exit code and the same five results
on every fixture in the corpus. A disagreement between them on any input is
a soundness bug in one of them.

### Exit codes

| Code | Word | Meaning |
| --- | --- | --- |
| 0 | PASS | every result that was checked holds, signing identity included |
| 1 | FAIL | content integrity, scope, redactions or a key window failed. This includes a bundle with required files missing or unreadable, and a zip archive that cannot be extracted: evidence with pieces deleted must never pass |
| 2 | ERROR | usage, a path that does not exist, a manifest that is missing or carries an unknown format id, or an input beyond a documented limit. Nothing was verified either way |
| 3 | UNCONFIRMED | every integrity result holds, but the signing identity or the timestamps could not be confirmed: the mathematics is sound and the provenance is not established. Not a pass, and not evidence of tampering |

### Results

A run reports five results, each `pass`, `fail`, `unconfirmed` or
`not_checked`:

| Result | Covers |
| --- | --- |
| `content_integrity` | the hash chain, payload hashes, Merkle roots, checkpoint hashes and signatures, the checkpoint chain, the files the manifest lists, the SigilSign cross-checks, the recorded consistency states, and the shape of every file the format names |
| `signing_identity` | whether the checkpoint signatures are by a key in the trusted set, sealed inside that key's window |
| `timestamps` | the RFC 3161 anchors, against the timestamp trust roots the verifier carries |
| `scope` | whether the checkpoints cover exactly the range the manifest declares |
| `redactions` | whether every absent payload is named by an authenticated declaration |

Every result starts as `pass` and is only ever demoted, in the order
`pass`, `not_checked`, `unconfirmed`, `fail`; a demotion never reverses, so
the order in which checks run cannot change a verdict. The exit code is the
five results combined: any `fail` exits 1; otherwise any `unconfirmed`
exits 3; otherwise 0. `not_checked` says that nothing of the kind was
present to check (a bundle without anchors, or `--skip-anchors`), which is
not the same as checked and sound, and never changes the exit code on its
own.

Which result a failed check demotes is fixed: a check that belongs to no
other result demotes `content_integrity`, the largest category and the safe
direction for anything unnamed. The following demote another result:

- `signing_identity`: a checkpoint signed by a key outside the trusted set
  (`unconfirmed`); a checkpoint dated outside its trusted key's window
  (`fail`). The same window check against a key that is only in the
  manifest, not in the trusted set, demotes `content_integrity`, because
  the manifest is the bundle's own claim about itself.
- `timestamps`: every failure `anchor_validate` reports for a token
  (`fail`); a token that validates only against roots the bundle supplied,
  or with no roots available (`unconfirmed`); anchors absent, empty or
  skipped (`not_checked`). An anchor over a checkpoint hash the bundle does
  not carry, a token that is not base64, that does not match its
  `token_hash` or that does not parse demotes `content_integrity`.
- `scope`: the checkpoints covering up to a sequence other than the
  manifest's `range.to`.
- `redactions`: everything the declaration rule reports.

### Flags

Both commands accept the same flags, each as `--flag value` and, for the
flags that take a value, as `--flag=value`:

| Flag | Effect |
| --- | --- |
| `--keys <file>` | trust these signing keys instead of the built-in set, in the shape of the `/api/v1/keys` response: a non-empty `keys` list of objects each carrying a string `public_key` (hex of the raw 32 bytes) and, optionally, string `created_at` and `retired_at`. The file replaces the built-in set wholesale. A missing file, a document without a non-empty `keys` list, or an entry without a string `public_key` is an ERROR |
| `--tsa-roots <file>` | trust these timestamp-authority roots (PEM) instead of the built-in ones, wholesale. A missing file is an ERROR. A file with no PEM certificate blocks fails every anchor |
| `--skip-anchors` | do not validate the RFC 3161 anchors; `timestamps` becomes `not_checked` when anchors are present |
| `--json` | one machine-readable document on stdout, conforming to `result.schema.json`, and nothing else |
| `--quiet` | no output at all, on either stream; the exit code is the whole answer, and it wins over `--json` |
| `--print-hashes` | also report the SHA-256 of each bundle file argument (a directory is not hashed) |
| `--consistency` | with two bundles, prove the second is an append-only extension of the first; with one bundle plus `--root <hex>` and `--size <n>`, prove the bundle extends a previously recorded tree state. `--root` is lowercased; `--size` is read with PHP's integer cast, so `1e3` is 1000 and `abc` is 0 |
| `--help`, `-h` | the usage text on stdout, exit 0 |

An argument starting with `--` that is none of the above is an ERROR
("unknown option"), reported in the output mode the flags before it had
established. Any other argument is a bundle path. Without `--consistency`
exactly one bundle path is required; with it, either two bundle paths and
neither `--root` nor `--size`, or one bundle path and both. Anything else
is an ERROR.

### Output

Every run prints the implementation's name, version and the SHA-256 of the
file that ran (`verify.php` itself, or the `sigilbase-verify` binary), so a
reader can say which verifier produced a report. Under `--json` these are
the three identity fields and they are the only fields, together with the
free text of `failures`, `notes` and `message`, on which the two
implementations may differ; everything else in the document is equal for
the same input and options. The human report of `sigilbase-verify` begins
with the verdict word; `verify.php` ends with it. Both print each of the
five results, every signing key used with where trust in it came from
(the built-in trusted set, the `--keys` file, or the bundle alone), each
redaction on its own line, and, on a pass of a bundle that starts at
sequence 1, the consistency state to record.

### Trust material

Each release compiles `keys/sigilbase.json` and `keys/tsa-roots.pem` into
both implementations (`tools/compile-keys.php` for `verify.php`, Go's embed
for `sigilbase-verify` from its mirrored copy), and a test in each holds
the embedded copy to the file. Signing keys are matched on their public key bytes, never on a name
or an id the bundle supplies. A checkpoint signed by a key that is not in
the trusted set makes `signing_identity` unconfirmed; the bundle's manifest
cannot vouch for whose keys it carries.

Timestamp trust roots come from the embedded file or from `--tsa-roots`,
and from nowhere else: the operating system's certificate store is never
consulted, and a root found only inside a bundle's `ca_pem` or inside a
token never establishes trust. When the verifier carries roots, every
anchor's signer must chain to one of them, so a bundle anchored by an
authority whose root the verifier does not carry fails `timestamps` rather
than passing; pass `--tsa-roots` with that authority's root to settle it.
Only when the verifier carries no roots at all does a bundle-supplied
`ca_pem` get used, and then the anchor is `unconfirmed`; with neither, the
anchor's token and imprint are still checked and the result is
`unconfirmed`.

### Modes

`--consistency <old> <new>` verifies both bundles in full, then requires the
same stream, both ranges starting at sequence 1, the old range no longer
than the new, and, with no failures so far, that the new bundle's first
`old.range.to` entries hash to the old bundle's root; the RFC 6962 proof
between the two states is generated and verified, and the document reports
both states and the proof's node count. `--consistency <bundle> --root
<hex> --size <n>` verifies the bundle, then requires a range starting at
sequence 1, `1 <= n <= range.to`, a 64-character hex root, and that the
bundle's first `n` entries hash to the recorded root. Both modes combine
the results of every bundle they verified: an unconfirmed signing identity
in either bundle makes the run UNCONFIRMED.

## Parsing

Two verifiers can only agree on hostile input if they read the bytes the
same way. The rules below are those of `verify.php`, which reads JSON with
PHP's `json_decode` in object mode and archives with PHP's ZipArchive on
Linux; each is pinned by a vector in `vectors/vectors.json` or a fixture in
`corpus/hostile/`, and `sigilbase-verify` reproduces each with its own
parser rather than a general-purpose one.

### JSON documents and lines

- Every file is UTF-8 and must be well-formed throughout (RFC 3629: no
  overlong sequences, no encoded surrogates, nothing above U+10FFFF, no
  truncated sequences), inside strings and outside them. A violation makes
  the document, or the line, invalid.
- Escapes are the JSON ones: quotation mark, reverse solidus, solidus, and
  the letters b, f, n, r, t, plus the four-hex-digit form in either case.
  A high surrogate escape must be followed immediately by a low surrogate
  escape and the pair is one code point; a lone surrogate escape of either
  kind makes the line invalid. An escaped NUL is allowed in a value. Any
  other escape is invalid.
- A raw byte below 0x20 inside a string makes the line invalid; 0x7F is
  allowed.
- Only space, tab, LF and CR are whitespace, before and after the document.
  A form feed, a vertical tab, a NUL or a no-break space outside a string
  makes the document invalid. A byte order mark at the start makes the
  document invalid. Empty input, and anything after the document (including
  a second document), is invalid.
- Numbers follow the JSON grammar exactly: no leading zeros, no leading
  plus, no bare fraction. A literal with no fraction and no exponent is an
  integer when it fits a signed 64-bit integer (nineteen digits compare
  against 9223372036854775808; the negative bound is included) and a float
  otherwise; any literal with a fraction or an exponent is a float, `1.0`
  and `1e2` included. `-0` is the integer 0. Floats parse but cannot be
  canonicalised (below), and every field the format types as an integer
  requires an integer.
- An object key that is non-empty and begins with a NUL byte makes the
  document invalid (a PHP property cannot start with NUL). The empty key
  and a NUL later in a key are allowed.
- A duplicated key keeps its first position and takes its last value. A
  line with a duplicated key hashes over the last value, so a duplicate
  whose last value is the sealed one still verifies.
- Nesting is limited to 511 containers counted from the outermost; a 512th
  nested array or object makes the document invalid. An event line is
  itself the first container.
- `events.ndjson` and `declarations.ndjson` are read one line at a time. A
  line ends at LF; every trailing CR and LF is removed; the last line needs
  no LF. A line consisting only of spaces, tabs, CRs, NULs and vertical
  tabs is skipped and still counts towards line numbers. Any other line is
  decoded as a document and must be a JSON object; otherwise it is
  reported as not valid JSON against the result the file belongs to, and
  the walk continues with the next line. A line holding only a form feed
  is not blank and is not valid JSON.
- Canonical JSON (the hashed form) is RFC 8785 with these consequences:
  a float anywhere in a hashed structure, or an integer whose magnitude
  exceeds 2^53-1, cannot be canonicalised. In a payload that is a
  `content_integrity` failure of the event ("payload cannot be
  canonicalised"); in a field of an entry, checkpoint or declaration
  preimage it is a failure of that record ("cannot be canonicalised", the
  hash cannot be recomputed). Strings are escaped only for quotation mark,
  reverse solidus, and the control characters (short forms for backspace,
  tab, LF, form feed and CR; four lowercase hex digits otherwise); 0x7F and
  every non-ASCII character are copied as they are. Object keys sort by
  their UTF-16 code units.

### Field types

The format says which fields are strings and which are integers; a bundle
can put anything there. Where a check compares text, a value is read as
PHP's `(string)` cast reads a scalar (`true` is `1`, `false` and `null` are
empty) and an array or object reads as empty text, so it can match no hash
and the check fails. Where a check requires an integer, only an integer
counts (`is_int`). A list the format expects (the manifest's
`signing_keys`, the recorded `checkpoint_states`) yields its elements when
it is an array, its property values when it is an object, and nothing when
it is a scalar. The recorded consistency proof's tree sizes are read with
PHP's `(int)` cast (a float truncates and wraps modulo 2^64 outside the
range, a numeric string is read, anything else is 0, an object is 1). A
chain link (`prev_hash`, `prev_checkpoint`) is compared with strict
equality against the previous record's raw `entry_hash` or
`checkpoint_hash` value, case-sensitively; the recomputation of a hash
compares against the lowercased text. `strtolower` is ASCII-only.

### Timestamps

A timestamp field (`created_at` of a checkpoint or of a trusted key) must
match `YYYY-MM-DDThh:mm:ss`, an optional fraction of one to six digits,
and `Z` or an offset `+hh:mm`/`-hh:mm`, with one allowance: a single
trailing LF is accepted (PCRE's `$` matches before a final newline).
Within that shape PHP's date parser accepts month 0 to 12, day 0 to 31,
hour 0 to 24, minute 0 to 59, second 0 to 60 and offset hours 0 to 24, and
normalises the excess (month 0 is December of the previous year, day 0 the
last day of the previous month, hour 24 the next day, second 60 the next
minute, 30 February the 2nd of March); anything beyond those bounds is
unparseable. A checkpoint whose `created_at` is unparseable cannot be
checked against its key's window and that is reported as a failure of the
window check. Comparisons are of exact instants including microseconds.
Inside a token, `GeneralizedTime` is `YYYYMMDDhhmmss`, an optional fraction
of one to six digits and `Z`, and `UTCTime` is `YYMMDDhhmmssZ` with years
50 to 99 meaning 1950 to 1999 and 00 to 49 meaning 2000 to 2049; both
accept a single trailing LF and normalise every component as `gmmktime`
does, and a `GeneralizedTime` year of 0 to 69 reads as 2000 to 2069 and 70
to 100 as 1970 to 2000.

### Zip archives

A bundle given as a zip archive is read exactly as PHP's ZipArchive would
have extracted it to a directory on Linux:

- Entries are taken in central directory order. Each name is normalised:
  repeated slashes collapse, `.` components vanish, `..` resolves against
  the components before it, an absolute name loses its leading slash, and
  what remains of a leading `../` chain is dropped (PHP drops everything
  up to the rightmost slash that follows a `.` or `:` character, so `../x`,
  `sub/../x`, `/x` and `c:/x` all extract as `x`, and `dir./x` as `x`).
- A later entry of the same normalised name replaces an earlier one: the
  last entry wins, including a `../events.ndjson` after `events.ndjson`.
  A name that normalises to nothing, to `..`, or to a directory that a
  file already occupies (or a file that a directory already occupies)
  makes the extraction fail, which is exit 1.
- Every entry is inflated during extraction: an entry with a bad CRC, an
  encrypted entry, or a compression method the reader does not support
  fails the extraction. Both readers support stored and deflated entries
  and bzip2; `verify.php` additionally reads whatever its libzip was built
  with (LZMA on some builds), `sigilbase-verify` does not.
- Entries the format does not name are ignored, wherever they sit. A
  bundle wrapped in a top-level folder has no `manifest.json` and is exit
  1. A backslash is not a path separator.
- A file is looked up by its exact name after the same normalisation; a
  `certificates/` path from the manifest must start with `certificates/`,
  must not contain `..`, and resolves as the file system would (`//` and
  `/./` collapse; a trailing slash names no file).

`verify.php` on Windows extracts with the Windows path rules and may treat
some of these names differently; the reference behaviour is Linux, where
the release pipeline runs both implementations.

### Limits

`sigilbase-verify` refuses, with exit 2, a line of `events.ndjson` or
`declarations.ndjson` longer than 64 MiB, any file it reads whole
(everything except the two line-oriented files and certificate PDFs) larger
than 512 MiB, and any single zip entry larger than 64 GiB when
decompressed. `verify.php` has no such limits of its own and stops with a
PHP memory error on the same inputs. Memory in `sigilbase-verify` is
otherwise bounded by the largest checkpoint window and the files read
whole, not by the number of events.

## Ed25519 acceptance

`verify.php` verifies checkpoint signatures through libsodium, and
libsodium's acceptance rules are normative. A signature is 64 bytes and a
public key 32 bytes, both given as hex; any other length does not verify,
and neither does an empty message. Beyond RFC 8032, libsodium rejects
before looking at the equation: a public key encoding whose y coordinate
is not below 2^255-19 (non-canonical), a public key that is one of the
points of order 1, 2, 4 or 8 (with either sign bit), and a signature whose
R is one of those points; a signature whose S is not below the group order
is rejected as it is everywhere. R is compared by its canonical encoding.
An implementation on a library that follows RFC 8032 alone (Go's
`crypto/ed25519` among them) accepts forged signatures under a small-order
public key and signatures with a small-order R, and must add those checks;
`vectors/vectors.json`, `ed25519_acceptance`, carries one case for each
rule, checked against libsodium, and `corpus/hostile/` carries the same
forgeries inside bundles.

## Anchor token algorithms

A token is RFC 3161 over CMS `SignedData`, read with a DER reader that
accepts long-form lengths of up to four bytes including non-minimal ones,
rejects indefinite lengths and tag numbers of 31 and above, and re-encodes
what it re-uses with minimal lengths. Accepted message imprint and
`digestAlgorithm` digests are SHA-256, SHA-384 and SHA-512; anything else
is "unsupported imprint algorithm" or "unsupported digest algorithm".
Accepted `signatureAlgorithm` values are `sha256WithRSAEncryption`,
`sha384WithRSAEncryption`, `sha512WithRSAEncryption`, `ecdsa-with-SHA256`,
`ecdsa-with-SHA384`, `ecdsa-with-SHA512`, and `rsaEncryption` with the
digest taken from `digestAlgorithm`; anything else is "unsupported
signature algorithm". The signature is verified with the signer
certificate's key family (RSA PKCS#1 v1.5 for an RSA key, ECDSA for an EC
key on P-256, P-384 or P-521) and the digest the algorithm names, as
OpenSSL's `openssl_verify` does; the OID's own family is not checked
against the key. The signer must be embedded in the token, matched by
issuer and serial; it must carry the timestamping extended key usage
(1.3.6.1.5.5.7.3.8) and be valid at `genTime`. Chain links are verified as
OpenSSL's `X509_verify` verifies them: the outer signature algorithm must
equal the `tbsCertificate` signature algorithm, and RSA PKCS#1 v1.5 with
MD5, SHA-1, SHA-224, SHA-256, SHA-384 or SHA-512, RSASSA-PSS (MGF1 with
the same digest), ECDSA with SHA-1 or a SHA-2 digest, and Ed25519 are
accepted. Every issuer on the chain is held to the CA rules above
(*Anchor token*), evaluated at `genTime` and never at the current time.
