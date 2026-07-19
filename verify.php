<?php

declare(strict_types=1);

/**
 * Sigilbase standalone evidence verifier.
 *
 * Usage:
 *   php verify.php <bundle.zip | extracted-bundle-directory>
 *   php verify.php --skip-anchors <bundle>
 *   php verify.php --consistency <old-bundle> <new-bundle>
 *   php verify.php --consistency <bundle> --root <hex> --size <n>
 *
 * Flags:
 *   --json          one machine-readable JSON document on stdout instead of the report
 *   --quiet         no output at all; the exit code is the whole answer
 *   --print-hashes  also report the SHA-256 of this verifier file and of the
 *                   bundle file(s), so you can record exactly what ran against what
 *   --skip-anchors  skip RFC 3161 anchor validation
 *
 * Verifies a Sigilbase evidence bundle without trusting the Sigilbase
 * application or database: every event hash is recomputed from the event's
 * own fields, the hash chain is re-walked, each checkpoint's Merkle root is
 * rebuilt from the events it covers, and every checkpoint signature is
 * checked against the Ed25519 public keys listed in the manifest.
 *
 * Bundles at format 1.1 may carry RFC 3161 timestamp tokens (anchors.json)
 * proving to a third party WHEN each checkpoint existed. When PHP's openssl
 * extension is present they are validated (token parses, its imprint is the
 * checkpoint hash, the CMS signature verifies, and — when a CA is provided —
 * the signer chains to it); without openssl the anchors are reported as
 * present-but-unverified, which is never a failure by itself. --skip-anchors
 * silences that.
 *
 * Bundles at format 1.2 may contain redacted events: the payload was
 * destroyed by the exporting tenant (hash-preserving redaction), every
 * hash and all metadata survive, and redactions.json declares each one.
 * A redacted event verifies through its preserved payload_hash — the
 * entry hash and the chain recompute exactly as if the payload were
 * present — and is reported plainly and counted in the summary. A payload
 * that is absent WITHOUT a matching declaration fails verification:
 * absence must be declared, never implied.
 *
 * Bundles at format 1.3 may carry informational qualified-TSA metadata on
 * anchors (provider name, jurisdiction, qualified flag, signer serial) and
 * Certificates of Evidence under certificates/, each listed in the
 * manifest with its SHA-256. The metadata is reported, never trusted: an
 * anchor's verdict rests on the token's cryptography and the provided
 * roots alone, and a claimed "qualified" status cannot rescue a token
 * that fails them. Certificates are documents about the evidence, not
 * evidence — their hashes are checked so tampering in transit is caught,
 * and a manifest-listed certificate missing from the bundle is a failure
 * (evidence with pieces deleted must never pass).
 *
 * --consistency proves one export extends another (RFC 6962 consistency
 * over the cumulative tree of entry hashes): give it two bundles that both
 * start at sequence 1, or one such bundle plus a previously recorded root.
 *
 * This file is deliberately self-contained: no Composer, no autoloading,
 * no imports from the Sigilbase application. It needs PHP >= 8.2 with the
 * always-present hash extension and ext-sodium (ext-zip only when given a
 * .zip rather than a directory; ext-openssl only to validate RFC 3161
 * anchors, and inability to check anchors is reported, never a failure).
 * Nothing else — even the UTF-16 conversion for canonical key ordering is
 * implemented below rather than requiring mbstring. The hash and
 * canonicalisation logic intentionally duplicates the application's
 * implementation — its independence is the point.
 *
 * Exit codes:
 *   0 = PASS — every check succeeded
 *   1 = FAIL — the bundle does not verify. This includes bundles with
 *       required files missing: evidence with pieces deleted must never pass.
 *   2 = usage or format error — bad arguments, a path that does not exist,
 *       or a manifest whose format id this verifier does not know; nothing
 *       was verified either way.
 *
 * Versioning: semver, distinct from the bundle format version. See
 * FORMAT.md (alongside this file) for the format specification and the
 * verifier/format compatibility table. This file makes no network calls
 * of any kind.
 */
const VERIFIER_VERSION = '1.3.0';

error_reporting(E_ALL);

// ---------------------------------------------------------------------------
// Output modes
// ---------------------------------------------------------------------------

$quiet = false;         // --quiet: exit code only, nothing on stdout or stderr
$jsonMode = false;      // --json: one JSON document on stdout, nothing else
$printHashes = false;   // --print-hashes: report verifier + bundle SHA-256s
$failures = [];         // every FAIL line, verbatim
$notes = [];            // every NOTE line, verbatim
$bundleHashes = [];     // path => sha256 of each bundle FILE argument (dirs are null)

/**
 * All human-readable progress goes through here so --quiet and --json can
 * silence it wholesale.
 */
function out(string $text): void
{
    global $quiet, $jsonMode;

    if (! $quiet && ! $jsonMode) {
        fwrite(STDOUT, $text);
    }
}

/**
 * Emit the final verdict in whichever mode was requested, then exit 0 or 1.
 * Human-readable verdict lines are printed by the caller beforehand (they
 * differ per mode); this handles --print-hashes and --json uniformly.
 *
 * @param  array<string, mixed>  $document  mode-specific fields for --json
 */
function conclude(bool $pass, array $document): never
{
    global $failures, $notes, $jsonMode, $quiet, $printHashes, $bundleHashes;

    if ($printHashes) {
        out('Verifier sha256: '.hash_file('sha256', __FILE__)."\n");

        foreach ($bundleHashes as $path => $hash) {
            out('Bundle sha256:  '.($hash ?? '(directory, not hashed)')."  {$path}\n");
        }
    }

    if ($jsonMode && ! $quiet) {
        $document = [
            'verifier_version' => VERIFIER_VERSION,
            'result' => $pass ? 'pass' : 'fail',
            ...$document,
            'failures' => $failures,
            'notes' => $notes,
        ];

        if ($printHashes) {
            $document['verifier_sha256'] = hash_file('sha256', __FILE__);
            $document['bundle_sha256'] = $bundleHashes;
        }

        fwrite(STDOUT, json_encode($document, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES)."\n");
    }

    exit($pass ? 0 : 1);
}

// ---------------------------------------------------------------------------
// Canonical JSON (RFC 8785 subset: integers only, used for hash preimages)
// ---------------------------------------------------------------------------

/**
 * @throws RuntimeException
 */
function canonical_encode(mixed $value): string
{
    if ($value === null) {
        return 'null';
    }

    if (is_bool($value)) {
        return $value ? 'true' : 'false';
    }

    if (is_int($value)) {
        if ($value > 9007199254740991 || $value < -9007199254740991) {
            throw new RuntimeException('integer outside the exactly representable range');
        }

        return (string) $value;
    }

    if (is_float($value)) {
        throw new RuntimeException('non-integer numbers cannot be canonicalised');
    }

    if (is_string($value)) {
        return canonical_string($value);
    }

    if ($value instanceof stdClass) {
        return canonical_object((array) $value);
    }

    if (is_array($value)) {
        if ($value === [] || array_keys($value) === range(0, count($value) - 1)) {
            return '['.implode(',', array_map('canonical_encode', $value)).']';
        }

        return canonical_object($value);
    }

    throw new RuntimeException('unsupported value type '.get_debug_type($value));
}

function canonical_string(string $value): string
{
    $out = '"';
    $length = strlen($value);
    $i = 0;

    while ($i < $length) {
        $byte = $value[$i];
        $ord = ord($byte);

        if ($byte === '"') {
            $out .= '\\"';
        } elseif ($byte === '\\') {
            $out .= '\\\\';
        } elseif ($ord === 0x08) {
            $out .= '\\b';
        } elseif ($ord === 0x09) {
            $out .= '\\t';
        } elseif ($ord === 0x0A) {
            $out .= '\\n';
        } elseif ($ord === 0x0C) {
            $out .= '\\f';
        } elseif ($ord === 0x0D) {
            $out .= '\\r';
        } elseif ($ord < 0x20) {
            $out .= sprintf('\\u%04x', $ord);
        } else {
            $out .= $byte;
        }

        $i++;
    }

    return $out.'"';
}

/**
 * UTF-8 to UTF-16BE, implemented here so this file does not require the
 * mbstring extension (RFC 8785 sorts object keys by their UTF-16 code
 * units, and auditors' PHP builds do not always include mbstring). Input
 * comes from json_decode and is therefore valid UTF-8.
 */
function utf16be(string $utf8): string
{
    $out = '';
    $i = 0;
    $length = strlen($utf8);

    while ($i < $length) {
        $byte = ord($utf8[$i]);

        if ($byte < 0x80) {
            $codepoint = $byte;
            $i += 1;
        } elseif (($byte & 0xE0) === 0xC0) {
            $codepoint = (($byte & 0x1F) << 6) | (ord($utf8[$i + 1] ?? "\x00") & 0x3F);
            $i += 2;
        } elseif (($byte & 0xF0) === 0xE0) {
            $codepoint = (($byte & 0x0F) << 12)
                | ((ord($utf8[$i + 1] ?? "\x00") & 0x3F) << 6)
                | (ord($utf8[$i + 2] ?? "\x00") & 0x3F);
            $i += 3;
        } else {
            $codepoint = (($byte & 0x07) << 18)
                | ((ord($utf8[$i + 1] ?? "\x00") & 0x3F) << 12)
                | ((ord($utf8[$i + 2] ?? "\x00") & 0x3F) << 6)
                | (ord($utf8[$i + 3] ?? "\x00") & 0x3F);
            $i += 4;
        }

        if ($codepoint > 0xFFFF) {
            // Astral plane: encode as a UTF-16 surrogate pair.
            $codepoint -= 0x10000;
            $out .= pack('n', 0xD800 | ($codepoint >> 10)).pack('n', 0xDC00 | ($codepoint & 0x3FF));
        } else {
            $out .= pack('n', $codepoint);
        }
    }

    return $out;
}

/**
 * @param  array<array-key, mixed>  $members
 */
function canonical_object(array $members): string
{
    $sortable = [];

    foreach (array_keys($members) as $originalKey) {
        $key = (string) $originalKey;
        $utf16 = utf16be($key);
        $sortable[] = [$utf16, $key, $originalKey];
    }

    usort($sortable, static fn (array $a, array $b): int => strcmp($a[0], $b[0]));

    $parts = [];

    foreach ($sortable as [, $key, $originalKey]) {
        $parts[] = canonical_string($key).':'.canonical_encode($members[$originalKey]);
    }

    return '{'.implode(',', $parts).'}';
}

// ---------------------------------------------------------------------------
// RFC 6962 Merkle tree, inclusion, and consistency
// ---------------------------------------------------------------------------

/**
 * @param  list<string>  $leaves  raw 32-byte entry hashes
 */
function merkle_root(array $leaves): string
{
    $count = count($leaves);

    if ($count === 0) {
        throw new RuntimeException('cannot build a Merkle tree with zero leaves');
    }

    if ($count === 1) {
        return hash('sha256', "\x00".$leaves[0], true);
    }

    $split = merkle_split_point($count);

    return hash(
        'sha256',
        "\x01".merkle_root(array_slice($leaves, 0, $split)).merkle_root(array_slice($leaves, $split)),
        true,
    );
}

function merkle_split_point(int $count): int
{
    $split = 1;

    while ($split * 2 < $count) {
        $split *= 2;
    }

    return $split;
}

/**
 * RFC 6962 section 2.1.2 consistency proof from the first $oldSize leaves
 * to the whole tree, as raw 32-byte node hashes.
 *
 * @param  list<string>  $leaves
 * @return list<string>
 */
function consistency_proof(array $leaves, int $oldSize): array
{
    $newSize = count($leaves);

    if ($oldSize < 1 || $oldSize > $newSize) {
        throw new RuntimeException('old size out of range for consistency proof');
    }

    if ($oldSize === $newSize) {
        return [];
    }

    return consistency_subproof($oldSize, $leaves, true);
}

/**
 * @param  list<string>  $leaves
 * @return list<string>
 */
function consistency_subproof(int $oldSize, array $leaves, bool $oldTreeComplete): array
{
    $count = count($leaves);

    if ($oldSize === $count) {
        return $oldTreeComplete ? [] : [merkle_root($leaves)];
    }

    $split = merkle_split_point($count);

    if ($oldSize <= $split) {
        $proof = consistency_subproof($oldSize, array_slice($leaves, 0, $split), $oldTreeComplete);
        $proof[] = merkle_root(array_slice($leaves, $split));

        return $proof;
    }

    $proof = consistency_subproof($oldSize - $split, array_slice($leaves, $split), false);
    $proof[] = merkle_root(array_slice($leaves, 0, $split));

    return $proof;
}

/**
 * RFC 9162 section 2.1.4.2 consistency verification. Roots and proof nodes
 * are raw 32-byte hashes.
 *
 * @param  list<string>  $proof
 */
function consistency_verify(int $oldSize, int $newSize, string $oldRoot, string $newRoot, array $proof): bool
{
    if ($oldSize < 1 || $newSize < $oldSize) {
        return false;
    }

    if ($oldSize === $newSize) {
        return $proof === [] && hash_equals($oldRoot, $newRoot);
    }

    if ($proof === []) {
        return false;
    }

    if (($oldSize & ($oldSize - 1)) === 0) {
        array_unshift($proof, $oldRoot);
    }

    $fn = $oldSize - 1;
    $sn = $newSize - 1;

    while (($fn & 1) === 1) {
        $fn >>= 1;
        $sn >>= 1;
    }

    $fr = array_shift($proof);
    $sr = $fr;

    foreach ($proof as $node) {
        if ($sn === 0) {
            return false;
        }

        if (($fn & 1) === 1 || $fn === $sn) {
            $fr = hash('sha256', "\x01".$node.$fr, true);
            $sr = hash('sha256', "\x01".$node.$sr, true);

            while ($fn !== 0 && ($fn & 1) === 0) {
                $fn >>= 1;
                $sn >>= 1;
            }
        } else {
            $sr = hash('sha256', "\x01".$sr.$node, true);
        }

        $fn >>= 1;
        $sn >>= 1;
    }

    return $sn === 0 && hash_equals($oldRoot, $fr) && hash_equals($newRoot, $sr);
}

// ---------------------------------------------------------------------------
// Minimal DER reader (RFC 3161 anchor tokens; used only when openssl exists)
// ---------------------------------------------------------------------------

/**
 * @return array{class: int, constructed: bool, number: int, content: string, total: int}
 */
function der_read(string $der, int $offset = 0): array
{
    $available = strlen($der) - $offset;

    if ($available < 2) {
        throw new RuntimeException('truncated DER element');
    }

    $first = ord($der[$offset]);
    $number = $first & 0x1F;

    if ($number === 0x1F) {
        throw new RuntimeException('unsupported DER tag form');
    }

    $lengthByte = ord($der[$offset + 1]);
    $headerLength = 2;

    if ($lengthByte < 0x80) {
        $contentLength = $lengthByte;
    } else {
        $lengthOfLength = $lengthByte & 0x7F;

        if ($lengthOfLength === 0 || $lengthOfLength > 4 || $available < 2 + $lengthOfLength) {
            throw new RuntimeException('unsupported or truncated DER length');
        }

        $contentLength = 0;

        for ($i = 0; $i < $lengthOfLength; $i++) {
            $contentLength = ($contentLength << 8) | ord($der[$offset + 2 + $i]);
        }

        $headerLength += $lengthOfLength;
    }

    if ($available < $headerLength + $contentLength) {
        throw new RuntimeException('truncated DER content');
    }

    return [
        'class' => $first >> 6,
        'constructed' => ($first & 0x20) !== 0,
        'number' => $number,
        'content' => substr($der, $offset + $headerLength, $contentLength),
        'total' => $headerLength + $contentLength,
    ];
}

/**
 * @return list<array{class: int, constructed: bool, number: int, content: string, total: int}>
 */
function der_children(string $content): array
{
    $children = [];
    $offset = 0;
    $length = strlen($content);

    while ($offset < $length) {
        $child = der_read($content, $offset);
        $children[] = $child;
        $offset += $child['total'];
    }

    return $children;
}

/**
 * @param  array{class: int, constructed: bool, number: int, content: string, total: int}  $element
 */
function der_reencode(array $element): string
{
    $tag = ($element['class'] << 6) | ($element['constructed'] ? 0x20 : 0x00) | $element['number'];
    $length = strlen($element['content']);

    if ($length < 0x80) {
        return chr($tag).chr($length).$element['content'];
    }

    $bytes = '';

    while ($length > 0) {
        $bytes = chr($length & 0xFF).$bytes;
        $length >>= 8;
    }

    return chr($tag).chr(0x80 | strlen($bytes)).$bytes.$element['content'];
}

function der_decode_oid(string $content): string
{
    if ($content === '') {
        throw new RuntimeException('empty OID');
    }

    $first = ord($content[0]);

    $arcs = match (true) {
        $first < 40 => [0, $first],
        $first < 80 => [1, $first - 40],
        default => [2, $first - 80],
    };

    $value = 0;

    for ($i = 1, $length = strlen($content); $i < $length; $i++) {
        $byte = ord($content[$i]);
        $value = ($value << 7) | ($byte & 0x7F);

        if (($byte & 0x80) === 0) {
            $arcs[] = $value;
            $value = 0;
        }
    }

    return implode('.', $arcs);
}

function der_decode_generalized_time(string $content): int
{
    if (preg_match('/^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(?:\.\d{1,6})?Z$/', $content, $m) !== 1) {
        throw new RuntimeException("unsupported GeneralizedTime [{$content}]");
    }

    $timestamp = gmmktime((int) $m[4], (int) $m[5], (int) $m[6], (int) $m[2], (int) $m[3], (int) $m[1]);

    if ($timestamp === false) {
        throw new RuntimeException("unparseable GeneralizedTime [{$content}]");
    }

    return $timestamp;
}

// ---------------------------------------------------------------------------
// RFC 3161 anchor token parsing and validation
// ---------------------------------------------------------------------------

/**
 * Parse a DER TimeStampToken (CMS ContentInfo -> SignedData -> TSTInfo)
 * far enough to validate it. Throws RuntimeException on malformation.
 *
 * @return array{imprint_alg: string, imprint: string, gen_time: int, certs: list<string>, signer_issuer: string, signer_serial: string, signed_attrs_set: string, content_type_attr: string, message_digest_attr: string, digest_alg: string, sig_alg: string, signature: string, tst_info: string}
 */
function anchor_parse_token(string $der): array
{
    $contentInfo = der_read($der);
    $children = der_children($contentInfo['content']);

    if (count($children) < 2 || der_decode_oid($children[0]['content']) !== '1.2.840.113549.1.7.2') {
        throw new RuntimeException('token is not CMS SignedData');
    }

    $signedData = der_read($children[1]['content']);
    $fields = der_children($signedData['content']);

    if (count($fields) < 4) {
        throw new RuntimeException('SignedData is malformed');
    }

    $encap = der_children($fields[2]['content']);

    if ($encap === [] || der_decode_oid($encap[0]['content']) !== '1.2.840.113549.1.9.16.1.4') {
        throw new RuntimeException('eContentType is not id-ct-TSTInfo');
    }

    if (! isset($encap[1]) || $encap[1]['class'] !== 2) {
        throw new RuntimeException('SignedData carries no eContent');
    }

    $tstInfoDer = der_read($encap[1]['content'])['content'];

    $certs = [];
    $index = 3;

    while (isset($fields[$index]) && $fields[$index]['class'] === 2) {
        if ($fields[$index]['number'] === 0) {
            foreach (der_children($fields[$index]['content']) as $certificate) {
                $certs[] = der_reencode($certificate);
            }
        }

        $index++;
    }

    if (! isset($fields[$index]) || $fields[$index]['number'] !== 0x11) {
        throw new RuntimeException('SignedData has no signerInfos');
    }

    $signerInfos = der_children($fields[$index]['content']);

    if ($signerInfos === []) {
        throw new RuntimeException('signerInfos is empty');
    }

    $signer = der_children($signerInfos[0]['content']);

    if (count($signer) < 5 || $signer[1]['number'] !== 0x10 || $signer[1]['class'] !== 0) {
        throw new RuntimeException('SignerInfo sid is not issuerAndSerialNumber');
    }

    $sid = der_children($signer[1]['content']);
    $digestAlg = der_children($signer[2]['content']);

    if (count($sid) < 2 || $digestAlg === []) {
        throw new RuntimeException('SignerInfo is malformed');
    }

    if ($signer[3]['class'] !== 2 || $signer[3]['number'] !== 0) {
        throw new RuntimeException('SignerInfo has no signed attributes');
    }

    $signedAttrsContent = $signer[3]['content'];
    $contentTypeAttr = '';
    $messageDigestAttr = '';

    foreach (der_children($signedAttrsContent) as $attribute) {
        $parts = der_children($attribute['content']);

        if (count($parts) < 2) {
            continue;
        }

        $attrOid = der_decode_oid($parts[0]['content']);
        $values = der_children($parts[1]['content']);

        if ($values === []) {
            continue;
        }

        if ($attrOid === '1.2.840.113549.1.9.3') {
            $contentTypeAttr = der_decode_oid($values[0]['content']);
        }

        if ($attrOid === '1.2.840.113549.1.9.4') {
            $messageDigestAttr = $values[0]['content'];
        }
    }

    if ($contentTypeAttr === '' || $messageDigestAttr === '') {
        throw new RuntimeException('signed attributes lack contentType or messageDigest');
    }

    $sigAlg = der_children($signer[4]['content']);

    if ($sigAlg === [] || ! isset($signer[5]) || $signer[5]['number'] !== 0x04) {
        throw new RuntimeException('SignerInfo signature is malformed');
    }

    // TSTInfo: version, policy, messageImprint{alg, digest}, serial, genTime.
    $tstInfo = der_children(der_read($tstInfoDer)['content']);

    if (count($tstInfo) < 5) {
        throw new RuntimeException('TSTInfo is malformed');
    }

    $imprint = der_children($tstInfo[2]['content']);
    $imprintAlg = der_children($imprint[0]['content'] ?? '');

    if (count($imprint) < 2 || $imprintAlg === []) {
        throw new RuntimeException('TSTInfo messageImprint is malformed');
    }

    // Signature input: the signed attributes re-tagged as SET OF (RFC 5652 §5.4).
    $setLength = strlen($signedAttrsContent);
    $signedAttrsSet = $setLength < 0x80
        ? chr(0x31).chr($setLength).$signedAttrsContent
        : der_reencode(['class' => 0, 'constructed' => true, 'number' => 0x11, 'content' => $signedAttrsContent, 'total' => 0]);

    return [
        'imprint_alg' => der_decode_oid($imprintAlg[0]['content']),
        'imprint' => $imprint[1]['content'],
        'gen_time' => der_decode_generalized_time($tstInfo[4]['content']),
        'certs' => $certs,
        'signer_issuer' => der_reencode($sid[0]),
        'signer_serial' => ltrim($sid[1]['content'], "\x00"),
        'signed_attrs_set' => $signedAttrsSet,
        'content_type_attr' => $contentTypeAttr,
        'message_digest_attr' => $messageDigestAttr,
        'digest_alg' => der_decode_oid($digestAlg[0]['content']),
        'sig_alg' => der_decode_oid($sigAlg[0]['content']),
        'signature' => $signer[5]['content'],
        'tst_info' => $tstInfoDer,
    ];
}

/**
 * @return array{serial: string, issuer: string, subject: string}
 */
function anchor_cert_parts(string $certificateDer): array
{
    $certificate = der_read($certificateDer);
    $children = der_children($certificate['content']);

    if ($children === []) {
        throw new RuntimeException('certificate is malformed');
    }

    $tbs = der_children($children[0]['content']);
    $base = (isset($tbs[0]) && $tbs[0]['class'] === 2) ? 1 : 0;

    if (count($tbs) < $base + 6) {
        throw new RuntimeException('tbsCertificate is malformed');
    }

    return [
        'serial' => ltrim($tbs[$base]['content'], "\x00"),
        'issuer' => der_reencode($tbs[$base + 2]),
        'subject' => der_reencode($tbs[$base + 4]),
    ];
}

function anchor_der_to_pem(string $der): string
{
    return "-----BEGIN CERTIFICATE-----\n".chunk_split(base64_encode($der), 64, "\n").'-----END CERTIFICATE-----';
}

/**
 * @return list<string> DER certificates in a PEM bundle string
 */
function anchor_pem_certificates(string $pem): array
{
    preg_match_all('/-----BEGIN CERTIFICATE-----(.+?)-----END CERTIFICATE-----/s', $pem, $matches);

    $certificates = [];

    foreach ($matches[1] as $body) {
        $der = base64_decode((string) preg_replace('/\s+/', '', $body), true);

        if (is_string($der) && $der !== '') {
            $certificates[] = $der;
        }
    }

    return $certificates;
}

/**
 * Validate one parsed token against the message it must attest to.
 * Requires ext-openssl (the caller checks). $caPem may be null: chain
 * verification is then skipped and reported by the caller.
 *
 * @param  array{imprint_alg: string, imprint: string, gen_time: int, certs: list<string>, signer_issuer: string, signer_serial: string, signed_attrs_set: string, content_type_attr: string, message_digest_attr: string, digest_alg: string, sig_alg: string, signature: string, tst_info: string}  $token
 * @return list<string> failures
 */
function anchor_validate(array $token, string $message, ?string $caPem): array
{
    $failures = [];

    $digests = [
        '2.16.840.1.101.3.4.2.1' => 'sha256',
        '2.16.840.1.101.3.4.2.2' => 'sha384',
        '2.16.840.1.101.3.4.2.3' => 'sha512',
    ];

    if (($digests[$token['imprint_alg']] ?? null) === null) {
        $failures[] = "unsupported imprint algorithm [{$token['imprint_alg']}]";
    } elseif (! hash_equals(hash($digests[$token['imprint_alg']], $message, true), $token['imprint'])) {
        $failures[] = 'the token message imprint does not match the checkpoint hash';
    }

    if ($token['content_type_attr'] !== '1.2.840.113549.1.9.16.1.4') {
        $failures[] = 'the signed contentType attribute is not id-ct-TSTInfo';
    }

    $digest = $digests[$token['digest_alg']] ?? null;

    if ($digest === null) {
        $failures[] = "unsupported digest algorithm [{$token['digest_alg']}]";

        return $failures;
    }

    if (! hash_equals(hash($digest, $token['tst_info'], true), $token['message_digest_attr'])) {
        $failures[] = 'the messageDigest attribute does not match the TSTInfo content';
    }

    // The signer certificate must be embedded (Sigilbase requests certReq).
    $signerCert = null;

    foreach ($token['certs'] as $certificateDer) {
        try {
            $parts = anchor_cert_parts($certificateDer);
        } catch (RuntimeException) {
            continue;
        }

        if ($parts['serial'] === $token['signer_serial'] && $parts['issuer'] === $token['signer_issuer']) {
            $signerCert = $certificateDer;

            break;
        }
    }

    if ($signerCert === null) {
        $failures[] = 'the signer certificate is not embedded in the token';

        return $failures;
    }

    $algorithms = [
        '1.2.840.113549.1.1.11' => OPENSSL_ALGO_SHA256,
        '1.2.840.113549.1.1.12' => OPENSSL_ALGO_SHA384,
        '1.2.840.113549.1.1.13' => OPENSSL_ALGO_SHA512,
        '1.2.840.10045.4.3.2' => OPENSSL_ALGO_SHA256,
        '1.2.840.10045.4.3.3' => OPENSSL_ALGO_SHA384,
        '1.2.840.10045.4.3.4' => OPENSSL_ALGO_SHA512,
        '1.2.840.113549.1.1.1' => [
            'sha256' => OPENSSL_ALGO_SHA256,
            'sha384' => OPENSSL_ALGO_SHA384,
            'sha512' => OPENSSL_ALGO_SHA512,
        ][$digest] ?? null,
    ];

    $algorithm = $algorithms[$token['sig_alg']] ?? null;

    if ($algorithm === null) {
        $failures[] = "unsupported signature algorithm [{$token['sig_alg']}]";

        return $failures;
    }

    // The @ on openssl calls is deliberate: hostile bytes make them emit
    // warnings before returning false, and the false return already is the
    // clean failure.
    $publicKey = @openssl_pkey_get_public(anchor_der_to_pem($signerCert));

    if ($publicKey === false || @openssl_verify($token['signed_attrs_set'], $token['signature'], $publicKey, $algorithm) !== 1) {
        $failures[] = 'the CMS signature over the signed attributes does not verify';
    }

    $parsed = @openssl_x509_parse(anchor_der_to_pem($signerCert));

    if ($parsed === false) {
        $failures[] = 'the signer certificate does not parse';
    } else {
        if ($token['gen_time'] < (int) ($parsed['validFrom_time_t'] ?? 0) || $token['gen_time'] > (int) ($parsed['validTo_time_t'] ?? 0)) {
            $failures[] = 'the signer certificate was not valid at genTime';
        }

        $eku = (string) ($parsed['extensions']['extendedKeyUsage'] ?? '');

        if (! str_contains($eku, 'Time Stamping') && ! str_contains($eku, '1.3.6.1.5.5.7.3.8')) {
            $failures[] = 'the signer certificate lacks the timestamping extended key usage';
        }
    }

    if ($caPem !== null) {
        $anchors = anchor_pem_certificates($caPem);

        if ($anchors === []) {
            $failures[] = 'the provided CA chain contains no certificates';

            return $failures;
        }

        $anchorSet = array_flip(array_map('sha1', $anchors));
        $pool = [...$token['certs'], ...$anchors];
        $current = $signerCert;
        $seen = [];

        for ($depth = 0; $depth < 8; $depth++) {
            $fingerprint = sha1($current);

            if (isset($seen[$fingerprint])) {
                $failures[] = 'the certificate chain loops';

                return $failures;
            }

            $seen[$fingerprint] = true;

            try {
                $parts = anchor_cert_parts($current);
            } catch (RuntimeException) {
                $failures[] = 'a certificate in the chain does not parse';

                return $failures;
            }

            if ($parts['issuer'] === $parts['subject']) {
                if (! isset($anchorSet[$fingerprint])) {
                    $failures[] = 'the chain terminates at a root that is not in the provided CA';
                }

                return $failures;
            }

            $issuer = null;

            foreach ($pool as $candidate) {
                try {
                    if (anchor_cert_parts($candidate)['subject'] === $parts['issuer']) {
                        $issuer = $candidate;

                        break;
                    }
                } catch (RuntimeException) {
                    continue;
                }
            }

            if ($issuer === null) {
                $failures[] = 'the certificate chain is incomplete: an issuer certificate is missing';

                return $failures;
            }

            $certificate = @openssl_x509_read(anchor_der_to_pem($current));
            $issuerKey = @openssl_pkey_get_public(anchor_der_to_pem($issuer));

            if ($certificate === false || $issuerKey === false || @openssl_x509_verify($certificate, $issuerKey) !== 1) {
                $failures[] = 'a certificate signature in the chain does not verify';

                return $failures;
            }

            $current = $issuer;
        }

        $failures[] = 'the certificate chain is too deep';
    }

    return $failures;
}

// ---------------------------------------------------------------------------
// Bundle loading
// ---------------------------------------------------------------------------

/**
 * @return array{dir: string, cleanup: ?string}
 */
function locate_bundle(string $argument): array
{
    if (is_dir($argument)) {
        return ['dir' => rtrim($argument, '/\\'), 'cleanup' => null];
    }

    if (! is_file($argument)) {
        fail_hard("bundle [{$argument}] does not exist", 2);
    }

    if (! class_exists(ZipArchive::class)) {
        fail_hard('the zip extension is unavailable; extract the bundle and pass the directory instead', 2);
    }

    $temp = sys_get_temp_dir().DIRECTORY_SEPARATOR.'sigilbase-verify-'.bin2hex(random_bytes(6));

    if (! mkdir($temp, 0700, true)) {
        fail_hard("could not create temp directory [{$temp}]");
    }

    $zip = new ZipArchive;

    if ($zip->open($argument) !== true) {
        fail_hard("could not open zip [{$argument}]");
    }

    if (! $zip->extractTo($temp)) {
        fail_hard("could not extract zip [{$argument}]");
    }

    $zip->close();

    return ['dir' => $temp, 'cleanup' => $temp];
}

function read_bundle_file(string $dir, string $name): string
{
    $path = $dir.DIRECTORY_SEPARATOR.$name;

    if (! is_file($path)) {
        fail_hard("bundle is missing [{$name}]");
    }

    return (string) file_get_contents($path);
}

function cleanup_bundle(?string $path): void
{
    if ($path === null) {
        return;
    }

    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($path, FilesystemIterator::SKIP_DOTS),
        RecursiveIteratorIterator::CHILD_FIRST,
    );

    foreach ($iterator as $item) {
        $item->isDir() ? rmdir($item->getPathname()) : unlink($item->getPathname());
    }

    rmdir($path);
}

/**
 * Abort without a verdict-by-recomputation: exit 1 when the bundle cannot
 * pass (missing pieces are indistinguishable from deletion), exit 2 when
 * nothing was verified at all (usage/format errors).
 */
function fail_hard(string $message, int $code = 1): never
{
    global $quiet, $jsonMode;

    if ($jsonMode && ! $quiet) {
        fwrite(STDOUT, json_encode([
            'verifier_version' => VERIFIER_VERSION,
            'result' => 'error',
            'exit_code' => $code,
            'message' => $message,
        ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES)."\n");
    } elseif (! $quiet) {
        fwrite(STDERR, "FAIL: {$message}\n");
    }

    exit($code);
}

// ---------------------------------------------------------------------------
// Bundle verification
// ---------------------------------------------------------------------------

function report(string $message): void
{
    global $failures;

    $failures[] = $message;
    out("  FAIL {$message}\n");
}

function note(string $message): void
{
    global $notes;

    $notes[] = $message;
    out("  NOTE {$message}\n");
}

/**
 * Fully verify one bundle. Prints progress; failures land in the global
 * list AND the returned array.
 *
 * @return array{stream_id: string, range_from: int, range_to: int, event_count: int, checkpoint_count: int, entry_hashes: array<int, string>, failures: list<string>}
 */
function verify_bundle(string $target, bool $skipAnchors): array
{
    global $failures;

    $before = count($failures);

    $bundle = locate_bundle($target);
    $dir = $bundle['dir'];

    $manifest = json_decode(read_bundle_file($dir, 'manifest.json'), false);

    $format = $manifest instanceof stdClass ? ($manifest->format ?? null) : null;

    if (! in_array($format, ['sigilbase-evidence/1', 'sigilbase-evidence/1.1', 'sigilbase-evidence/1.2', 'sigilbase-evidence/1.3'], true)) {
        fail_hard('manifest.json is missing or has an unknown format (expected sigilbase-evidence/1, /1.1, /1.2 or /1.3)', 2);
    }

    $streamId = $manifest->stream->id ?? null;
    $rangeFrom = $manifest->range->from ?? null;
    $rangeTo = $manifest->range->to ?? null;

    if (! is_string($streamId) || ! is_int($rangeFrom) || ! is_int($rangeTo)) {
        fail_hard('manifest.json is missing stream id or range');
    }

    $trustedKeys = [];

    foreach ($manifest->signing_keys ?? [] as $key) {
        if (isset($key->public_key) && is_string($key->public_key)) {
            $trustedKeys[strtolower($key->public_key)] = true;
        }
    }

    if ($trustedKeys === []) {
        fail_hard('manifest.json lists no signing keys');
    }

    out("Stream: {$streamId}\n");
    out("Range:  {$rangeFrom}..{$rangeTo}\n");
    out('Keys:   '.count($trustedKeys)." trusted signing key(s) in manifest\n\n");

    // ---- redactions.json (1.2, optional) -------------------------------------

    // The redactions manifest declares every event whose payload the tenant
    // destroyed. It is read before the events so the chain walk below can
    // demand a declaration for every absent payload. A missing file means
    // "no redactions declared" — absent payloads then fail.
    $redactionsBySequence = [];
    $redactionsPath = $dir.DIRECTORY_SEPARATOR.'redactions.json';

    if (is_file($redactionsPath)) {
        $redactionsDocument = json_decode((string) file_get_contents($redactionsPath), false);
        $redactionRecords = $redactionsDocument instanceof stdClass ? ($redactionsDocument->redactions ?? null) : null;

        if (! is_array($redactionRecords)) {
            report('redactions.json is present but malformed — expected a "redactions" list');
        } else {
            foreach ($redactionRecords as $record) {
                $declaredSequence = $record instanceof stdClass ? ($record->sequence ?? null) : null;

                if (! is_int($declaredSequence)) {
                    report('redactions.json contains an entry without an integer sequence');

                    continue;
                }

                if ($declaredSequence < $rangeFrom || $declaredSequence > $rangeTo) {
                    note("redactions.json declares sequence {$declaredSequence}, outside this bundle's range");

                    continue;
                }

                $redactionsBySequence[$declaredSequence] = $record;
            }
        }
    }

    // ---- events.ndjson -----------------------------------------------------

    out("Checking events.ndjson (hash chain)...\n");

    $eventLines = preg_split('/\r?\n/', trim(read_bundle_file($dir, 'events.ndjson')));
    $events = [];

    foreach ($eventLines as $lineNumber => $line) {
        if ($line === '') {
            continue;
        }

        $event = json_decode($line, false);

        if (! $event instanceof stdClass) {
            report('events.ndjson line '.($lineNumber + 1).' is not valid JSON');

            continue;
        }

        $events[] = $event;
    }

    if ($events === []) {
        fail_hard('events.ndjson contains no events');
    }

    $expectedSequence = $rangeFrom;

    // A range starting at sequence 1 must chain from the 32-zero-byte hash;
    // ranges starting later trust the first event's prev and verify onwards.
    $prevHash = $rangeFrom === 1 ? str_repeat('0', 64) : null;

    $entryHashBySequence = [];
    $redactedCount = 0;

    foreach ($events as $event) {
        $sequence = $event->seq ?? null;

        if (! is_int($sequence)) {
            report('an event is missing its sequence number');

            continue;
        }

        if ($sequence !== $expectedSequence) {
            report("sequence {$sequence}: expected sequence {$expectedSequence} here — an event was deleted, inserted, or reordered");
        }

        // Payload hash: recompute from the payload content itself — except
        // for a redacted event, whose content no longer exists. Redaction
        // is only accepted when every signal agrees: payload_state says
        // "redacted", the payload is null, and redactions.json declares
        // the sequence. Anything less is a failure — an absent payload is
        // never quietly acceptable.
        $payloadState = $event->payload_state ?? 'present';
        $payloadPresent = ($event->payload ?? null) !== null;
        $declaration = $redactionsBySequence[$sequence] ?? null;

        if (! in_array($payloadState, ['present', 'redacted'], true)) {
            report("sequence {$sequence}: unknown payload_state ".json_encode($payloadState));
        } elseif ($payloadState === 'redacted' || ! $payloadPresent) {
            if ($payloadPresent) {
                report("sequence {$sequence}: payload_state says redacted but a payload is present — the bundle contradicts itself");
            } elseif ($payloadState !== 'redacted') {
                report("sequence {$sequence}: payload is absent but not marked payload_state \"redacted\" — absence must be declared, never implied");
            } elseif ($declaration === null) {
                report("sequence {$sequence}: payload is absent without a redactions.json entry — absence must be declared, never implied");
            } else {
                $redactedCount++;
                $redactedAt = is_string($declaration->redacted_at ?? null) ? substr($declaration->redacted_at, 0, 10) : 'an undeclared date';
                note("sequence {$sequence}: payload redacted {$redactedAt}, hashes preserved, chain verified from the recorded payload_hash");
            }
        } else {
            if ($declaration !== null) {
                report("sequence {$sequence}: redactions.json declares this payload redacted but it is present — the bundle contradicts itself");
            }

            try {
                $canonicalPayload = canonical_encode($event->payload ?? null);
                $payloadHash = hash('sha256', $canonicalPayload);

                if (! hash_equals(strtolower((string) ($event->payload_hash ?? '')), $payloadHash)) {
                    report("sequence {$sequence}: payload_hash does not match the payload content — the payload was modified");
                }
            } catch (RuntimeException $exception) {
                report("sequence {$sequence}: payload cannot be canonicalised ({$exception->getMessage()})");
            }
        }

        // Chain link: each event must reference the previous entry hash.
        if ($prevHash !== null && ($event->prev_hash ?? null) !== $prevHash) {
            report("sequence {$sequence}: prev_hash does not match the previous entry hash — the chain is broken here");
        }

        // Entry hash: recompute the v1 preimage from the event's own fields.
        $preimage = canonical_encode((object) [
            'v' => 1,
            'stream' => $streamId,
            'seq' => $sequence,
            'occurred_at' => $event->occurred_at ?? null,
            'received_at' => $event->received_at ?? null,
            'actor' => $event->actor ?? null,
            'action' => $event->action ?? null,
            'resource' => $event->resource ?? null,
            'payload_hash' => $event->payload_hash ?? null,
            'prev' => $event->prev_hash ?? null,
        ]);

        $recomputed = hash('sha256', $preimage);

        if (! hash_equals(strtolower((string) ($event->entry_hash ?? '')), $recomputed)) {
            report("sequence {$sequence}: entry_hash does not recompute from the stored fields — a field was modified");
        }

        $entryHashBySequence[$sequence] = strtolower((string) ($event->entry_hash ?? ''));
        $prevHash = $event->entry_hash ?? null;
        $expectedSequence = $sequence + 1;
    }

    $lastSequence = $expectedSequence - 1;

    if ($lastSequence !== $rangeTo) {
        report("events end at sequence {$lastSequence} but the manifest declares {$rangeTo} — trailing events are missing");
    }

    // ---- checkpoints.json --------------------------------------------------

    out("Checking checkpoints.json (signed Merkle checkpoints)...\n");

    $checkpointDocument = json_decode(read_bundle_file($dir, 'checkpoints.json'), false);
    $checkpoints = $checkpointDocument->checkpoints ?? null;

    if (! is_array($checkpoints) || $checkpoints === []) {
        fail_hard('checkpoints.json contains no checkpoints');
    }

    $prevCheckpointHash = $rangeFrom === 1 ? str_repeat('0', 64) : null;
    $expectedFrom = $rangeFrom;
    $checkpointHashes = [];

    foreach ($checkpoints as $checkpoint) {
        $from = $checkpoint->from ?? null;
        $to = $checkpoint->to ?? null;

        if (! is_int($from) || ! is_int($to)) {
            report('a checkpoint is missing its range');

            continue;
        }

        if ($from !== $expectedFrom) {
            report("checkpoint {$from}..{$to}: expected the range to start at {$expectedFrom} — a checkpoint is missing or reordered");
        }

        // Checkpoint hash: recompute the v1 preimage.
        $preimage = canonical_encode((object) [
            'v' => 1,
            'stream' => $streamId,
            'from' => $from,
            'to' => $to,
            'root' => $checkpoint->root ?? null,
            'prev_checkpoint' => $checkpoint->prev_checkpoint ?? null,
            'created_at' => $checkpoint->created_at ?? null,
        ]);

        $recomputedHash = hash('sha256', $preimage);
        $declaredHash = strtolower((string) ($checkpoint->checkpoint_hash ?? ''));

        if (! hash_equals($declaredHash, $recomputedHash)) {
            report("checkpoint {$from}..{$to}: checkpoint_hash does not recompute from its fields — the checkpoint was modified");
        }

        // Chain link between checkpoints.
        if ($prevCheckpointHash !== null && ($checkpoint->prev_checkpoint ?? null) !== $prevCheckpointHash) {
            report("checkpoint {$from}..{$to}: prev_checkpoint does not match the previous checkpoint hash — a checkpoint was removed or replaced");
        }

        // Signature: Ed25519 over the raw checkpoint hash, key must be trusted.
        $publicKeyHex = strtolower((string) ($checkpoint->public_key ?? ''));

        if (! isset($trustedKeys[$publicKeyHex])) {
            report("checkpoint {$from}..{$to}: signed by a key that is not in the manifest's signing keys");
        }

        $signature = hex2bin((string) ($checkpoint->signature ?? ''));
        $message = hex2bin($declaredHash);
        $publicKey = hex2bin($publicKeyHex);

        $signatureValid = is_string($signature)
            && is_string($message)
            && is_string($publicKey)
            && strlen($signature) === SODIUM_CRYPTO_SIGN_BYTES
            && strlen($publicKey) === SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES
            && $message !== ''
            && sodium_crypto_sign_verify_detached($signature, $message, $publicKey);

        if (! $signatureValid) {
            report("checkpoint {$from}..{$to}: the Ed25519 signature does not verify — the signature is forged or the checkpoint was modified");
        }

        // Merkle root: rebuild from the entry hashes of the covered events.
        $leaves = [];
        $complete = true;

        for ($sequence = $from; $sequence <= $to; $sequence++) {
            if (! isset($entryHashBySequence[$sequence])) {
                report("checkpoint {$from}..{$to}: event {$sequence} is missing from events.ndjson");
                $complete = false;

                break;
            }

            $leaf = hex2bin($entryHashBySequence[$sequence]);

            if ($leaf === false) {
                $complete = false;

                break;
            }

            $leaves[] = $leaf;
        }

        if ($complete && $leaves !== []) {
            $rebuiltRoot = bin2hex(merkle_root($leaves));

            if (! hash_equals(strtolower((string) ($checkpoint->root ?? '')), $rebuiltRoot)) {
                report("checkpoint {$from}..{$to}: the Merkle root does not recompute from the events it covers");
            }
        }

        $checkpointHashes[$declaredHash] = true;
        $prevCheckpointHash = $checkpoint->checkpoint_hash ?? null;
        $expectedFrom = $to + 1;
    }

    $lastCovered = $expectedFrom - 1;

    if ($lastCovered !== $rangeTo) {
        report("checkpoints cover up to sequence {$lastCovered} but the manifest declares {$rangeTo}");
    }

    // ---- anchors.json (format 1.1, optional) --------------------------------

    $anchorsPath = $dir.DIRECTORY_SEPARATOR.'anchors.json';

    if (is_file($anchorsPath)) {
        $anchorDocument = json_decode((string) file_get_contents($anchorsPath), false);
        $anchors = is_object($anchorDocument) && is_array($anchorDocument->anchors ?? null) ? $anchorDocument->anchors : [];

        if ($anchors !== [] && $skipAnchors) {
            out('Skipping '.count($anchors)." RFC 3161 anchor token(s) (--skip-anchors).\n");
        } elseif ($anchors !== [] && ! extension_loaded('openssl')) {
            out("Checking anchors.json (RFC 3161 timestamps)...\n");
            note('anchors present, not verified (the openssl extension is unavailable); use --skip-anchors to silence');
        } elseif ($anchors !== []) {
            out("Checking anchors.json (RFC 3161 timestamps)...\n");

            foreach ($anchors as $index => $anchor) {
                $label = 'anchor #'.($index + 1).' ('.((string) ($anchor->provider ?? 'unknown')).')';
                $checkpointHash = strtolower((string) ($anchor->checkpoint_hash ?? ''));

                if (! isset($checkpointHashes[$checkpointHash])) {
                    report("{$label}: anchors a checkpoint hash that is not in this bundle");

                    continue;
                }

                $tokenDer = base64_decode((string) ($anchor->token ?? ''), true);

                if (! is_string($tokenDer) || $tokenDer === '') {
                    report("{$label}: the token is not valid base64");

                    continue;
                }

                if (! hash_equals(strtolower((string) ($anchor->token_hash ?? '')), hash('sha256', $tokenDer))) {
                    report("{$label}: the token does not match its recorded token_hash");

                    continue;
                }

                try {
                    $token = anchor_parse_token($tokenDer);
                } catch (RuntimeException $exception) {
                    report("{$label}: the token does not parse ({$exception->getMessage()})");

                    continue;
                }

                $caPem = isset($anchor->ca_pem) && is_string($anchor->ca_pem) && $anchor->ca_pem !== '' ? $anchor->ca_pem : null;

                foreach (anchor_validate($token, (string) hex2bin($checkpointHash), $caPem) as $problem) {
                    report("{$label}: {$problem}");
                }

                if ($caPem === null) {
                    note("{$label}: signature and imprint verified; no CA chain was provided, so the TSA identity was not verified");
                }

                // Informational qualified-TSA metadata (format 1.3). Reported
                // as-is and deliberately kept OUT of the verdict: the exporter
                // wrote these fields, and a claimed status is not evidence —
                // only the token's cryptography above is.
                if (($anchor->qualified ?? null) === true) {
                    $providerName = is_string($anchor->provider_name ?? null) ? $anchor->provider_name : (string) ($anchor->provider ?? 'unknown');
                    $jurisdiction = is_string($anchor->jurisdiction ?? null) ? " ({$anchor->jurisdiction})" : '';

                    note("{$label}: the exporter recorded this token as issued by a qualified trust service provider — {$providerName}{$jurisdiction}. Informational: the verdict rests on the cryptographic checks alone");
                }
            }
        }
    }

    // ---- certificates/ (format 1.3, optional, informational) -----------------

    $certificateRecords = is_array($manifest->certificates ?? null) ? $manifest->certificates : [];

    if ($certificateRecords !== []) {
        out('Checking '.count($certificateRecords)." Certificate(s) of Evidence (certificates/)...\n");

        foreach ($certificateRecords as $index => $record) {
            $recordId = is_string($record->id ?? null) ? $record->id : ('#'.($index + 1));
            $label = "certificate {$recordId}";

            $file = is_string($record->file ?? null) ? $record->file : null;

            if ($file === null || ! str_starts_with($file, 'certificates/') || str_contains($file, '..')) {
                report("{$label}: the manifest entry has a missing or unsafe file path");

                continue;
            }

            $path = $dir.DIRECTORY_SEPARATOR.str_replace('/', DIRECTORY_SEPARATOR, $file);

            if (! is_file($path)) {
                report("{$label}: listed in the manifest but missing from the bundle");

                continue;
            }

            if (! hash_equals(strtolower((string) ($record->sha256 ?? '')), (string) hash_file('sha256', $path))) {
                report("{$label}: the file does not match its manifest sha256");
            }
        }

        note(count($certificateRecords).' Certificate(s) of Evidence travelled with this bundle. They are documents about the evidence; the cryptographic verification above does not depend on them');
    }

    // ---- consistency.json (format 1.1, optional) -----------------------------

    $consistencyPath = $dir.DIRECTORY_SEPARATOR.'consistency.json';

    if (is_file($consistencyPath) && $rangeFrom === 1) {
        out("Checking consistency.json (cumulative tree states)...\n");

        $consistency = json_decode((string) file_get_contents($consistencyPath), false);

        $cumulativeLeaves = [];

        for ($sequence = 1; $sequence <= $rangeTo; $sequence++) {
            $leaf = isset($entryHashBySequence[$sequence]) ? hex2bin($entryHashBySequence[$sequence]) : false;

            if (! is_string($leaf)) {
                break;
            }

            $cumulativeLeaves[] = $leaf;
        }

        if (count($cumulativeLeaves) === $rangeTo && is_object($consistency)) {
            $declaredRoot = strtolower((string) ($consistency->root ?? ''));

            if (! hash_equals($declaredRoot, bin2hex(merkle_root($cumulativeLeaves)))) {
                report('consistency.json: the cumulative root does not recompute from the events');
            }

            foreach ($consistency->checkpoint_states ?? [] as $state) {
                $size = $state->tree_size ?? null;

                if (! is_int($size) || $size < 1 || $size > $rangeTo) {
                    report('consistency.json: a checkpoint state has an invalid tree_size');

                    continue;
                }

                $stateRoot = bin2hex(merkle_root(array_slice($cumulativeLeaves, 0, $size)));

                if (! hash_equals(strtolower((string) ($state->root ?? '')), $stateRoot)) {
                    report("consistency.json: the recorded root for tree_size {$size} does not recompute");
                }
            }

            $proof = $consistency->proof ?? null;

            if (is_object($proof)) {
                $nodes = [];

                foreach ((array) ($proof->nodes ?? []) as $hex) {
                    $node = is_string($hex) ? hex2bin($hex) : false;

                    if (is_string($node)) {
                        $nodes[] = $node;
                    }
                }

                $fromSize = (int) ($proof->from_tree_size ?? 0);
                $toSize = (int) ($proof->to_tree_size ?? 0);

                $valid = $fromSize >= 1 && $toSize === $rangeTo && consistency_verify(
                    $fromSize,
                    $toSize,
                    merkle_root(array_slice($cumulativeLeaves, 0, $fromSize)),
                    merkle_root($cumulativeLeaves),
                    $nodes,
                );

                if (! $valid) {
                    report('consistency.json: the recorded consistency proof does not verify');
                }
            }
        }
    }

    cleanup_bundle($bundle['cleanup']);

    return [
        'stream_id' => $streamId,
        'range_from' => $rangeFrom,
        'range_to' => $rangeTo,
        'event_count' => count($events),
        'checkpoint_count' => count($checkpoints),
        'redacted_count' => $redactedCount,
        'entry_hashes' => $entryHashBySequence,
        'failures' => array_slice($failures, $before),
    ];
}

// ---------------------------------------------------------------------------
// Entrypoint
// ---------------------------------------------------------------------------

// When this file is require()d — by the test suite, or by anyone wanting
// the canonicalisation/Merkle functions as a library — stop here.
// Everything above is functions; everything below is the CLI.
if (realpath($_SERVER['SCRIPT_FILENAME'] ?? '') !== __FILE__) {
    return;
}

$arguments = array_slice($argv, 1);
$skipAnchors = false;
$consistencyMode = false;
$recordedRoot = null;
$recordedSize = null;
$targets = [];

for ($i = 0; $i < count($arguments); $i++) {
    $argument = $arguments[$i];

    if ($argument === '--skip-anchors') {
        $skipAnchors = true;
    } elseif ($argument === '--consistency') {
        $consistencyMode = true;
    } elseif ($argument === '--json') {
        $jsonMode = true;
    } elseif ($argument === '--quiet') {
        $quiet = true;
    } elseif ($argument === '--print-hashes') {
        $printHashes = true;
    } elseif ($argument === '--root') {
        $recordedRoot = strtolower((string) ($arguments[++$i] ?? ''));
    } elseif (str_starts_with($argument, '--root=')) {
        $recordedRoot = strtolower(substr($argument, 7));
    } elseif ($argument === '--size') {
        $recordedSize = (int) ($arguments[++$i] ?? 0);
    } elseif (str_starts_with($argument, '--size=')) {
        $recordedSize = (int) substr($argument, 7);
    } elseif (str_starts_with($argument, '--')) {
        fail_hard("unknown option [{$argument}]", 2);
    } else {
        $targets[] = $argument;
    }
}

$usage = "usage: php verify.php [--skip-anchors] [--json] [--quiet] [--print-hashes] <bundle.zip | extracted-bundle-directory>\n"
    ."       php verify.php --consistency <old-bundle> <new-bundle>\n"
    ."       php verify.php --consistency <bundle> --root <hex> --size <n>\n";

foreach ($targets as $target) {
    $bundleHashes[$target] = is_file($target) ? hash_file('sha256', $target) : null;
}

out('Sigilbase evidence verifier v'.VERIFIER_VERSION."\n");

if (! $consistencyMode) {
    if (count($targets) !== 1) {
        if (! $quiet && ! $jsonMode) {
            fwrite(STDERR, $usage);
        }

        fail_hard('expected exactly one bundle argument', 2);
    }

    out("Bundle: {$targets[0]}\n\n");

    $result = verify_bundle($targets[0], $skipAnchors);

    out("\n");

    $consistencyState = null;

    if ($failures === []) {
        out("PASS: {$result['event_count']} events and {$result['checkpoint_count']} checkpoints verified for stream {$result['stream_id']} ({$result['range_from']}..{$result['range_to']}).\n");
        out("No event has been modified, deleted, or reordered, and every checkpoint signature is genuine.\n");

        if ($result['redacted_count'] > 0) {
            out("Redactions: {$result['redacted_count']} payload(s) were redacted by the tenant and are declared in redactions.json; their hashes are preserved and the chain is intact.\n");
        }

        if ($result['range_from'] === 1) {
            $leaves = [];

            for ($sequence = 1; $sequence <= $result['range_to']; $sequence++) {
                $leaves[] = (string) hex2bin($result['entry_hashes'][$sequence]);
            }

            $consistencyState = ['tree_size' => $result['range_to'], 'root' => bin2hex(merkle_root($leaves))];

            out("Consistency state: tree_size={$consistencyState['tree_size']} root={$consistencyState['root']}\n");
            out("Record these two values: a future export can prove it extends this one (--consistency).\n");
        }
    } else {
        out('FAIL: '.count($failures)." problem(s) found. This bundle does NOT verify.\n");
    }

    conclude($failures === [], [
        'mode' => 'verify',
        'bundle' => [
            'path' => $targets[0],
            'stream' => $result['stream_id'],
            'range' => ['from' => $result['range_from'], 'to' => $result['range_to']],
            'events' => $result['event_count'],
            'checkpoints' => $result['checkpoint_count'],
            'redacted_events' => $result['redacted_count'],
        ],
        'consistency_state' => $consistencyState,
    ]);
}

// ---- consistency mode -------------------------------------------------------

if (count($targets) === 2 && $recordedRoot === null && $recordedSize === null) {
    out("Mode:   consistency between two bundles\n\n");
    out("=== Old bundle: {$targets[0]} ===\n\n");

    $old = verify_bundle($targets[0], $skipAnchors);

    out("\n=== New bundle: {$targets[1]} ===\n\n");

    $new = verify_bundle($targets[1], $skipAnchors);

    out("\nChecking consistency (RFC 6962)...\n");

    if ($old['stream_id'] !== $new['stream_id']) {
        report('the bundles are for different streams');
    }

    if ($old['range_from'] !== 1 || $new['range_from'] !== 1) {
        report('consistency requires both bundles to start at sequence 1 (cumulative roots are only computable from the full log)');
    }

    if ($old['range_to'] > $new['range_to']) {
        report('the old bundle covers more events than the new one — pass the older bundle first');
    }

    $consistency = null;

    if ($failures === []) {
        $oldLeaves = [];
        $newLeaves = [];

        for ($sequence = 1; $sequence <= $old['range_to']; $sequence++) {
            $oldLeaves[] = (string) hex2bin($old['entry_hashes'][$sequence]);
        }

        for ($sequence = 1; $sequence <= $new['range_to']; $sequence++) {
            $newLeaves[] = (string) hex2bin($new['entry_hashes'][$sequence]);
        }

        $oldRoot = merkle_root($oldLeaves);
        $newRoot = merkle_root($newLeaves);
        $prefixRoot = merkle_root(array_slice($newLeaves, 0, $old['range_to']));

        if (! hash_equals($oldRoot, $prefixRoot)) {
            report('the new bundle does NOT extend the old one: its first '.$old['range_to'].' entries hash to a different root — history diverged');
        } else {
            $proof = consistency_proof($newLeaves, $old['range_to']);

            if (! consistency_verify($old['range_to'], $new['range_to'], $oldRoot, $newRoot, $proof)) {
                report('internal error: the generated consistency proof does not verify');
            } else {
                $consistency = [
                    'old' => ['tree_size' => $old['range_to'], 'root' => bin2hex($oldRoot)],
                    'new' => ['tree_size' => $new['range_to'], 'root' => bin2hex($newRoot)],
                    'proof_nodes' => count($proof),
                ];

                out('  old  tree_size='.$old['range_to'].' root='.bin2hex($oldRoot)."\n");
                out('  new  tree_size='.$new['range_to'].' root='.bin2hex($newRoot)."\n");
                out('  proof '.count($proof)." node(s) verified\n");
            }
        }
    }

    out("\n");

    if ($failures === []) {
        out("PASS: the new bundle is an append-only extension of the old bundle.\n");
        out("Nothing recorded in the old export was modified, deleted, or reordered in the new one.\n");
    } else {
        out('FAIL: '.count($failures)." problem(s) found. Consistency does NOT hold.\n");
    }

    conclude($failures === [], [
        'mode' => 'consistency-bundles',
        'bundles' => [
            ['path' => $targets[0], 'stream' => $old['stream_id'], 'range' => ['from' => $old['range_from'], 'to' => $old['range_to']]],
            ['path' => $targets[1], 'stream' => $new['stream_id'], 'range' => ['from' => $new['range_from'], 'to' => $new['range_to']]],
        ],
        'consistency' => $consistency,
    ]);
}

if (count($targets) === 1 && is_string($recordedRoot) && is_int($recordedSize)) {
    out("Mode:   consistency against a recorded root\n\n");
    out("Bundle: {$targets[0]}\n\n");

    $bundle = verify_bundle($targets[0], $skipAnchors);

    out("\nChecking consistency (RFC 6962)...\n");

    if ($bundle['range_from'] !== 1) {
        report('consistency requires the bundle to start at sequence 1');
    } elseif ($recordedSize < 1 || $recordedSize > $bundle['range_to']) {
        report("the recorded size {$recordedSize} is outside this bundle's range");
    } elseif (strlen($recordedRoot) !== 64 || ! ctype_xdigit($recordedRoot)) {
        report('the recorded root is not a 64-character hex hash');
    } else {
        $leaves = [];

        for ($sequence = 1; $sequence <= $recordedSize; $sequence++) {
            $leaves[] = (string) hex2bin($bundle['entry_hashes'][$sequence]);
        }

        $prefixRoot = bin2hex(merkle_root($leaves));

        if (! hash_equals($recordedRoot, $prefixRoot)) {
            report("this bundle does NOT extend the recorded state: its first {$recordedSize} entries hash to {$prefixRoot}, not the recorded root");
        } else {
            out("  recorded tree_size={$recordedSize} root={$recordedRoot} — matches this bundle's prefix\n");
        }
    }

    out("\n");

    if ($failures === []) {
        out("PASS: this bundle is an append-only extension of the recorded state.\n");
    } else {
        out('FAIL: '.count($failures)." problem(s) found. Consistency does NOT hold.\n");
    }

    conclude($failures === [], [
        'mode' => 'consistency-recorded-root',
        'bundle' => [
            'path' => $targets[0],
            'stream' => $bundle['stream_id'],
            'range' => ['from' => $bundle['range_from'], 'to' => $bundle['range_to']],
        ],
        'recorded' => ['tree_size' => $recordedSize, 'root' => $recordedRoot],
    ]);
}

if (! $quiet && ! $jsonMode) {
    fwrite(STDERR, $usage);
}

fail_hard('invalid combination of arguments', 2);
