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
php verify.php --print-hashes the-bundle-you-received.zip

# 3. Later, prove a newer export extends this one with nothing rewritten.
php verify.php --consistency the-bundle-you-received.zip the-newer-bundle.zip
```

Every bundle also contains its own copy of `verify.php`, so step 1 works even
if you only have the bundle. Running the copy from this repository instead —
after comparing its hash with a release you trust — removes the bundle
itself from the trust equation entirely.

**What PASS means.** No event in the bundle differs by one byte from what
was sealed; within the exported range nothing was removed, inserted, or
reordered; the sealed checkpoints chain together so a whole period cannot
have been quietly dropped; and every seal carries a valid Ed25519 signature
from a key listed in the bundle's manifest. To anchor that to Sigilbase's
identity rather than the bundle's own say-so, compare the manifest's
`signing_keys` against the keys the instance publishes at `/api/v1/keys`
(no credentials needed). If the bundle carries RFC 3161 anchor tokens, PASS
additionally means independent timestamping authorities attested the
checkpoints existed at the recorded times.

**What a failure means.** The output names the first thing that broke — the
exact event sequence or checkpoint and the nature of the problem (chain
break, hash mismatch, missing event, bad signature, checkpoint chain break).
A failing bundle does not verify; treat it as altered until someone explains
otherwise. Exit codes: `0` pass, `1` fail, `2` usage or format error
(nothing was verified either way).

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

Flags: `--json` for a machine-readable result document, `--quiet` for
exit-code-only, `--print-hashes` to record the SHA-256 of the verifier and
bundle, `--skip-anchors` to skip anchor validation, and `--consistency` to
prove one export extends another (two bundles, or one bundle plus a
previously recorded `--root <hex> --size <n>` pair).

### Compatibility

| Verifier | Bundle formats verified |
| --- | --- |
| 1.0.x | `sigilbase-evidence/1` (in-app only; never published) |
| 1.1.x | `sigilbase-evidence/1`, `sigilbase-evidence/1.1` |

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
