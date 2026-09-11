# verifier

The standalone, open verifier for Sigilbase evidence bundles. One PHP file, no dependencies, no network access — it recomputes
every hash and checks every signature from the bundle's own bytes, so you do
not have to trust Sigilbase (or whoever handed you the bundle) to confirm
that nothing was modified, deleted, or reordered after ingestion.

## If you have been handed a bundle

You need PHP 8.2 or newer (`php -v` to check; any Linux, macOS, or Windows
build works). Then:

```bash
# 1. Verify the bundle. Exit code 0 and "PASS" mean every check held.
php verify.php the-bundle-you-received.zip

# 2. Record what you ran against what (keep these hashes with your notes).
#    A passing bundle that starts at sequence 1 also prints a consistency
#    root; keep it, and step 3 can prove a later export extends this one.
php verify.php --print-hashes the-bundle-you-received.zip

# 3. Later, prove a newer export extends this one with nothing rewritten.
php verify.php --consistency the-bundle-you-received.zip the-newer-bundle.zip
```

Every bundle also contains its own copy of `verify.php`, so step 1 works even
if you only have the bundle. Running the copy from this repository instead —
after comparing its hash with a release you trust — removes the bundle
itself from the trust equation entirely.

**Five results.** A verification answers five questions separately,
because what was proved and who proved it are not the same question:

| Result | What it covers |
| --- | --- |
| Content integrity | The hash chain, payload hashes, Merkle roots and checkpoint signatures |
| Signing identity | Whether those signatures are by a key this verifier trusts, sealed inside that key's window |
| Timestamps | The RFC 3161 anchors, against trust roots this verifier carries |
| Scope | The range and completeness the manifest claims |
| Redactions | Whether every absent payload is named by an authenticated declaration |

**What PASS means.** No event in the bundle differs by one byte from what
was sealed; within the exported range nothing was removed, inserted, or
reordered; the sealed checkpoints chain together so a whole period cannot
have been quietly dropped; every seal carries a valid Ed25519 signature;
and the keys that made those signatures are ones this verifier already
trusted. If the bundle carries RFC 3161 anchor tokens and you supplied the
authority's roots, PASS additionally means independent timestamping
authorities attested the checkpoints existed at the recorded times.

**What UNCONFIRMED means.** The maths holds and the origin is not
established. The bundle is internally sound — nothing in it has been
altered — and it was signed by a key this verifier does not carry, or its
timestamps chain only to a root the bundle itself supplied. That is not
evidence of tampering and it is not a pass: anyone can produce a hash chain
and sign it with a key of their own, so a bundle cannot vouch for whose
keys it carries. You will see it on a bundle from a private deployment, on
a test bundle, and on a bundle somebody rebuilt and re-signed.

**Choosing what to trust.** This verifier carries Sigilbase's signing keys,
compiled in from `keys/sigilbase.json` and matched on the public key bytes.
`--keys <file>` replaces that set entirely, in the shape of the
`/api/v1/keys` response, so you can fetch the keys yourself and check
against what you fetched rather than against what we shipped.
`--tsa-roots <file>` does the same for timestamp authorities.

**What a failure means.** The output names the first thing that broke — the
exact event sequence or checkpoint and the nature of the problem (chain
break, hash mismatch, missing event, bad signature, checkpoint chain break).
A failing bundle does not verify; treat it as altered until someone explains
otherwise. Exit codes: `0` PASS, `1` FAIL, `2` ERROR (usage, an unreadable
bundle or an unknown format — nothing was verified either way), `3`
UNCONFIRMED.

**Check which verifier you ran.** Every run prints this file's version and
sha256. Compare them with the [release
notes](https://github.com/sigilbase/verifier/releases): a verifier is only
as trustworthy as the file you actually ran, and that line is what lets you
say which one it was.

**What verification does not prove.** Honesty about limits is part of the
guarantee. It does not prove events were *true* when written — if a system
recorded that a backup succeeded when it did not, the false statement is
sealed faithfully; tamper-evidence starts at ingestion. It does not prove
the exported range is the whole story — whether other streams or periods
exist is an audit-scoping question. It does not cover the minutes between
an event arriving and its checkpoint being sealed. And it does not identify
people: `actor` is whatever the writing system claimed; the record of the
claim is what is protected.

## For engineers evaluating the claims

`verify.php` is deliberately a single file with no Composer dependencies,
no autoloading, and no network calls of any kind (no update checks either —
the test suite asserts the absence of every network-capable construct). It
requires PHP ≥ 8.2 with `ext-sodium` and the always-present `hash`
extension; `ext-zip` only to open `.zip` bundles directly (extract the
bundle and pass the directory otherwise); `ext-openssl` only to validate
RFC 3161 anchor tokens, and *inability* to validate anchors is reported,
never treated as a failure. Even the UTF-16 conversion used for canonical
key ordering is implemented in the file rather than requiring mbstring.

The verification stages, in order (function names in the file mirror
these): manifest checks, per-event hash recomputation, hash-chain walk,
per-checkpoint RFC 6962 Merkle root rebuild, checkpoint chain walk and
Ed25519 signature checks, RFC 3161 anchor validation (format 1.1), and
cumulative-tree consistency checks. The bundle format is specified
normatively in [FORMAT.md](FORMAT.md); the mathematics are RFC 8785
(canonical JSON), RFC 6962 (Merkle trees and consistency proofs, verified
per RFC 9162 §2.1.4.2), Ed25519, and RFC 3161/5652 (timestamp tokens).

Flags: `--keys <file>` and `--tsa-roots <file>` to replace the trusted
signing keys and timestamp roots, `--json` for a machine-readable result
document, `--quiet` for exit-code-only, `--print-hashes` to record the
SHA-256 of each bundle file, `--skip-anchors` to skip anchor validation,
`--consistency` to prove one export extends another (two bundles, or one
bundle plus a previously recorded `--root <hex> --size <n>` pair), and
`--help`.

### Compatibility

| Verifier | Bundle formats verified |
| --- | --- |
| 1.0.x | `sigilbase-evidence/1` (in-app only; never published) |
| 1.1.x | `sigilbase-evidence/1`, `sigilbase-evidence/1.1` |
| 1.2.x | `sigilbase-evidence/1` through `sigilbase-evidence/1.2` |
| 1.3.x | `sigilbase-evidence/1` through `sigilbase-evidence/1.3` |
| 1.4.x | `sigilbase-evidence/1` through `sigilbase-evidence/1.4` |
| 1.5.x | `sigilbase-evidence/1` through `sigilbase-evidence/1.5` |

Format 1.3 bundles may carry informational qualified-TSA metadata on
anchors and Certificates of Evidence under `certificates/`. The metadata
is reported, never trusted — an anchor's verdict rests on the token's
cryptography and the provided roots alone — and certificates are checked
against their manifest hashes so tampering in transit is caught. Format
1.4 adds the SigilSign blocks, cross-checked against the events. From
1.4.1 the anchor chain walk holds every issuer to CA rules (basicConstraints
`cA`, `keyCertSign`, validity at `genTime`, `pathLenConstraint`), so a
"timestamping" signer issued by an ordinary end-entity certificate under a
trusted root fails; see FORMAT.md, *Anchor token*. From 1.4.2 every
checkpoint must be dated inside its signing key's active window, so a
retired key cannot vouch for checkpoints sealed after its retirement; see
FORMAT.md, *Checkpoint signature*. Format 1.5 carries the declarations
that destroyed any absent payload, so an absence is accepted only against
one that authenticates and names that exact event; the verifier reports
five results and four exit codes, carries a trusted signing key set that
`--keys` replaces, and reads `events.ndjson` a line at a time so bundle
size does not decide who can verify.

### Running the tests

```bash
composer install   # dev-only: PHPUnit. The verifier itself needs nothing.
composer test
```

The suite generates bundles from scratch (its own Ed25519 keys, canonical
JSON, Merkle trees), verifies them, then tampers with them in every way the
format defends against and asserts each is rejected with the right named
failure and exit code.

## Security

Verifier soundness bugs — anything that could make tampered evidence pass —
are treated as critical. See [SECURITY.md](SECURITY.md) for private
reporting.

## License

Apache-2.0. See [LICENSE](LICENSE).
