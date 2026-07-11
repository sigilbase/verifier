# Security policy

## Reporting a vulnerability

Please report verifier bugs privately to **TODO_EMAIL** rather than opening
a public issue. Include the verifier version (`php verify.php` prints it),
your PHP version, and — if you can — a minimal bundle or byte sequence that
demonstrates the problem.

## Severity

This tool exists so that people do not have to trust Sigilbase. Accordingly,
**soundness bugs are treated as critical**: anything that could make a
tampered bundle PASS, accept a forged signature, mis-verify a Merkle root or
consistency proof, or validate an RFC 3161 token that does not attest to the
checkpoint it claims to. Crashes and hangs on hostile input are treated as
high severity. Cosmetic and usability issues are welcome as ordinary public
issues.

There is no bug bounty at this time; reports are credited in release notes
unless you prefer otherwise.

## Scope notes

The verifier makes no network calls of any kind and has no runtime
dependencies; reports about the behaviour of PHP itself or its bundled
extensions should go to the PHP project, but we still want to hear about
them if they change what this verifier accepts.
