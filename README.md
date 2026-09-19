# verifier

The standalone, open verifier for Sigilbase evidence bundles, in two
implementations that release under one version number: `verify.php`, one
PHP file with no dependencies and no network access, in this repository,
and `sigilbase-verify`, a static Go binary with no third-party code, in
[sigilbase/verifier-go](https://github.com/sigilbase/verifier-go). Either
recomputes every hash and checks every signature from the bundle's own
bytes, so you do not have to trust Sigilbase (or whoever handed you the
bundle) to confirm that nothing was modified, deleted, or reordered after
ingestion. The two are held to the same answer on every fixture in the
conformance corpus; a difference between them is a bug in one of them,
treated as critical.

## If you have been handed a bundle

With PHP 8.2 or newer (`php -v` to check; any Linux, macOS, or Windows build
works):

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

Without PHP, with the `sigilbase-verify` binary for your platform from the
[verifier-go release page](https://github.com/sigilbase/verifier-go/releases)
(check its hash against `SHA256SUMS` there first), the same three steps:

```bash
# 1. Verify the bundle. Exit code 0 and "PASS" mean every check held.
sigilbase-verify the-bundle-you-received.zip

# 2. Record what you ran against what.
sigilbase-verify --print-hashes the-bundle-you-received.zip

# 3. Later, prove a newer export extends this one with nothing rewritten.
sigilbase-verify --consistency the-bundle-you-received.zip the-newer-bundle.zip
```

Every bundle also contains its own copy of `verify.php`, so step 1 works even
if you only have the bundle. Running the copy from this repository instead -
after comparing its hash with a release you trust - removes the bundle
itself from the trust equation entirely. The Go binary is never inside a
bundle; it comes from the release page or from a build you made yourself.

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
trusted. If the bundle carries RFC 3161 anchor tokens, PASS additionally
means independent timestamping authorities whose roots this verifier
carries attested the checkpoints existed at the recorded times.

**What UNCONFIRMED means.** The maths holds and the origin is not
established. The bundle is internally sound - nothing in it has been
altered - and it was signed by a key this verifier does not carry, or its
timestamps could not be tied to a root this verifier carries. That is not
evidence of tampering and it is not a pass: anyone can produce a hash chain
and sign it with a key of their own, so a bundle cannot vouch for whose
keys it carries. You will see it on a bundle from a private deployment, on
a test bundle, and on a bundle somebody rebuilt and re-signed.

**Choosing what to trust.** Both verifiers carry Sigilbase's signing keys,
compiled in from `keys/sigilbase.json` and matched on the public key bytes,
and the roots of the timestamp authorities production anchors use, from
`keys/tsa-roots.pem`. `--keys <file>` replaces the key set entirely, in the
shape of the `/api/v1/keys` response, so you can fetch the keys yourself and
check against what you fetched rather than against what we shipped.
`--tsa-roots <file>` does the same for timestamp authorities. A bundle
anchored by an authority whose root the verifier does not carry fails the
timestamps result until you name that root with `--tsa-roots`; a root that
travels inside the bundle never establishes trust on its own.

**What a failure means.** The output names the first thing that broke - the
exact event sequence or checkpoint and the nature of the problem (chain
break, hash mismatch, missing event, bad signature, checkpoint chain break).
A failing bundle does not verify; treat it as altered until someone explains
otherwise. Exit codes: `0` PASS, `1` FAIL, `2` ERROR (usage, an unreadable
bundle or an unknown format - nothing was verified either way), `3`
UNCONFIRMED.

**Check which verifier you ran.** Every run prints the implementation's
name, version and sha256 (of `verify.php` itself, or of the `sigilbase-verify`
binary). Compare them with the [release
notes](https://github.com/sigilbase/verifier/releases): a verifier is only
as trustworthy as the file you actually ran, and that line is what lets you
say which one it was.

**What verification does not prove.** Honesty about limits is part of the
guarantee. It does not prove events were *true* when written - if a system
recorded that a backup succeeded when it did not, the false statement is
sealed faithfully; tamper-evidence starts at ingestion. It does not prove
the exported range is the whole story - whether other streams or periods
exist is an audit-scoping question. It does not cover the minutes between
an event arriving and its checkpoint being sealed. And it does not identify
people: `actor` is whatever the writing system claimed; the record of the
claim is what is protected. The output makes no legal claim: it reports
what was checked and what was not.

## In a pipeline

The verifier-go repository carries a GitLab CI template
(`ci/gitlab/verify-bundle.gitlab-ci.yml`) and a GitHub Action
(`integrations/github-action/`). Each downloads a pinned release binary,
checks it against a sha256 you give in the workflow, runs it over a bundle
path, and fails the job on any exit code other than 0. UNCONFIRMED fails by
default; an explicit input allows it for private deployments. Neither makes
any network call beyond fetching the pinned release.

## For engineers evaluating the claims

`verify.php` is deliberately a single file with no Composer dependencies,
no autoloading, and no network calls of any kind (no update checks either -
the test suite asserts the absence of every network-capable construct). It
requires PHP >= 8.2 with `ext-sodium` and the always-present `hash`
extension; `ext-zip` only to open `.zip` bundles directly (extract the
bundle and pass the directory otherwise); `ext-openssl` only to validate
RFC 3161 anchor tokens, and *inability* to validate anchors is reported,
never treated as a failure. Even the UTF-16 conversion used for canonical
key ordering is implemented in the file rather than requiring mbstring.

`sigilbase-verify` is the same verifier in Go, standard library only, in
[sigilbase/verifier-go](https://github.com/sigilbase/verifier-go). It is a
peer of `verify.php`, not a port of it: [FORMAT.md](FORMAT.md),
`result.schema.json`, `vectors/vectors.json` and `corpus/` decide what is
correct, and that repository mirrors them at the same paths so a plain
diff shows the two are in step. Its own README covers building it
reproducibly, its tests, and the `verify` package other Sigilbase Go
programs import instead of reimplementing hashing or proofs.

The verification stages, in order (function names in `verify.php` mirror
these, and the Go packages name the PHP function each part mirrors):
manifest checks, per-event hash recomputation, hash-chain walk,
per-checkpoint RFC 6962 Merkle root rebuild, checkpoint chain walk and
Ed25519 signature checks, declaration checks (format 1.5), RFC 3161 anchor
validation (format 1.1), Certificate of Evidence and SigilSign cross-checks,
and cumulative-tree consistency checks. The mathematics are RFC 8785
(canonical JSON), RFC 6962 (Merkle trees and consistency proofs, verified
per RFC 9162 section 2.1.4.2), Ed25519 under libsodium's acceptance rules,
and RFC 3161/5652 (timestamp tokens).

Flags, identical in both: `--keys <file>` and `--tsa-roots <file>` to
replace the trusted signing keys and timestamp roots, `--json` for a
machine-readable result document (`result.schema.json`), `--quiet` for
exit-code-only, `--print-hashes` to record the SHA-256 of each bundle file,
`--skip-anchors` to skip anchor validation, `--consistency` to prove one
export extends another (two bundles, or one bundle plus a previously
recorded `--root <hex> --size <n>` pair), and `--help`.

### Compatibility

| Verifier | Bundle formats verified |
| --- | --- |
| 1.0.x | `sigilbase-evidence/1` (in-app only; never published) |
| 1.1.x | `sigilbase-evidence/1`, `sigilbase-evidence/1.1` |
| 1.2.x | `sigilbase-evidence/1` through `sigilbase-evidence/1.2` |
| 1.3.x | `sigilbase-evidence/1` through `sigilbase-evidence/1.3` |
| 1.4.x | `sigilbase-evidence/1` through `sigilbase-evidence/1.4` |
| 1.5.x | `sigilbase-evidence/1` through `sigilbase-evidence/1.5` |
| 1.6.x | `sigilbase-evidence/1` through `sigilbase-evidence/1.5`, in PHP and Go |

Format 1.3 bundles may carry informational qualified-TSA metadata on
anchors and Certificates of Evidence under `certificates/`. The metadata
is reported, never trusted - an anchor's verdict rests on the token's
cryptography and the provided roots alone - and certificates are checked
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
size does not decide who can verify. 1.6.0 adds the Go implementation,
pins the production timestamp roots, specifies parsing and Ed25519
acceptance so that two implementations cannot drift, and turns every input
that used to stop `verify.php` with a PHP error (a hostile field type, a
date its parser refuses) into a failure of that record.

### Running the tests

```bash
composer install   # dev-only: PHPUnit. verify.php itself needs nothing.
composer test
```

The suite generates bundles from scratch (its own Ed25519 keys, canonical
JSON, Merkle trees), verifies them, then tampers with them in every way the
format defends against and asserts each is rejected with the right named
failure and exit code. The corpus (`corpus/`, with its expectations in
`corpus/expected.json`) is shared with the Go implementation: CI checks out
verifier-go, runs both verifiers over every fixture here, and fails on any
difference; the same job checks that the mirrored files are identical.
`corpus/hostile/` holds one fixture per parsing rule, generated by
verifier-go's `tools/hostile`; the consistency fixtures come from
`php tools/build-corpus-consistency.php` here.

### Key rotation

A rotation is still a verifier release first: the release that carries the
new key in `keys/sigilbase.json` now carries it in both implementations,
`verify.php` through `php tools/compile-keys.php` and `sigilbase-verify`
through its embed of the mirrored file, and both release gates hold the
implementations to the file. The same holds for a new timestamp authority
root in `keys/tsa-roots.pem`.

## Security

Verifier soundness bugs - anything that could make tampered evidence pass,
in either implementation, or make the two implementations disagree - are
treated as critical. See [SECURITY.md](SECURITY.md) for private reporting.

## License

Apache-2.0. See [LICENSE](LICENSE).
