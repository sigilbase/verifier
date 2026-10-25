<?php

declare(strict_types=1);

/**
 * Builds the SigilSign and Certificate of Evidence fixtures in corpus/ with
 * tests/FixtureGenerator.php under the published corpus test key and a
 * fixed stream id, so the documents.json, signatures.json and links.json
 * cross-checks (format 1.4) and the certificates/ hash check (format 1.3)
 * have committed, reproducible inputs in both verifiers' differential runs:
 *
 *   sigilsign.zip                    a published document, a completed two-signer signing,
 *                                    a link and an unlink, a second version, and a
 *                                    certificate: every stated fact agrees with the chain
 *   sigilsign-document-sha.zip       documents.json states a hash the publication does not carry
 *   sigilsign-viewed-other.zip       a signer viewed one version and signed another
 *   sigilsign-claimed-signer.zip     signatures.json claims a signer no signature.signed event records
 *   sigilsign-signature-mark.zip     a stated signature-mark hash differs from the ledgered one
 *   sigilsign-no-signing-events.zip  a signing the chain never records
 *   sigilsign-link-action.zip        a link's linked_sequence names a document.published event
 *   sigilsign-link-sha.zip           a link states a hash its document.linked event does not carry
 *   sigilsign-malformed.zip          documents.json without a documents list
 *   sigilsign-numeric-members.zip    sigilsign.zip with integer-named members ("7", "0") holding
 *                                    integers, at the top of all three blocks, in each record
 *                                    and in a version and a signer: unknown fields, ignored
 *   sigilsign-float-seq.zip          sigilsign.zip with the first event's seq written 1.5: the
 *                                    chain fails, and the SigilSign pass reads it without a
 *                                    warning ahead of the --json document
 *   certificate-sha.zip              a certificate whose bytes do not match its manifest sha256
 *   certificate-missing.zip          a certificate listed in the manifest but not in the bundle
 *   certificate-unsafe-path.zip      a certificate listed at a path outside certificates/
 *
 * Run from the repository root:
 *
 *   php tools/build-corpus-sigilsign.php
 *
 * Exits 1 when a fixture changed, 0 when they were already up to date, so a
 * CI check can hold the committed files to this script. Fixtures are
 * compared by the bytes of their entries, not of the archive.
 */
require_once __DIR__.'/../vendor/autoload.php';

use Sigilbase\Verifier\Tests\FixtureGenerator;

$root = dirname(__DIR__);
$seed = '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60';
$stream = '019b7ca9-8c88-70c0-8000-0000000000d4';

$work = sys_get_temp_dir().DIRECTORY_SEPARATOR.'sigilbase-corpus-sigilsign-'.bin2hex(random_bytes(4));
mkdir($work, 0755, true);

$changed = false;

/**
 * @return array<string, string>|null
 */
$entries = static function (string $path): ?array {
    if (! is_file($path)) {
        return null;
    }

    $zip = new ZipArchive;

    if ($zip->open($path) !== true) {
        return null;
    }

    $out = [];

    for ($i = 0; $i < $zip->numFiles; $i++) {
        $name = (string) $zip->getNameIndex($i);
        $out[$name] = (string) $zip->getFromIndex($i);
    }

    $zip->close();
    ksort($out);

    return $out;
};

$json = static fn (mixed $value): string => json_encode($value, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);

// The document's two versions, the signature marks and the certificate.
$v1 = hash('sha256', 'Master services agreement, version 1');
$v2 = hash('sha256', 'Master services agreement, version 2');
$markA = hash('sha256', 'signature mark: ada');
$markB = hash('sha256', 'signature mark: grace');
$certificate = "%PDF-1.7\n% Certificate of Evidence (corpus fixture)\n%%EOF\n";
$certificateId = '019b7ca9-8c88-70c0-8000-00000000c001';
$signing = '019b7ca9-8c88-70c0-8000-00000000a001';

$at = static fn (int $minute): string => sprintf('2026-07-03T10:%02d:00.000000Z', $minute);

$event = static fn (int $minute, string $actor, string $action, ?string $resource, array $payload): array => [
    'occurred_at' => $at($minute),
    'received_at' => $at($minute),
    'actor' => $actor,
    'action' => $action,
    'resource' => $resource,
    'payload' => (object) $payload,
];

$signer = static fn (string $name, string $email): array => ['name' => $name, 'email' => $email];

/**
 * @return list<array<string, mixed>>
 */
$history = static fn (array $overrides = []): array => array_replace([
    1 => $event(1, 'user:owner', 'document.published', 'document:msa', ['document' => 'msa', 'version' => 1, 'sha256' => $v1, 'size_bytes' => 36]),
    2 => $event(2, 'user:owner', 'signature.requested', 'signing:'.$signing, ['document' => ['slug' => 'msa', 'version' => 1, 'sha256' => $v1], 'order' => 'sequential', 'signers' => 2]),
    3 => $event(3, 'signer:1', 'signature.viewed', 'signing:'.$signing, ['signer' => $signer('Ada', 'ada@example.com'), 'sha256' => $v1]),
    4 => $event(4, 'signer:1', 'signature.signed', 'signing:'.$signing, ['signer' => $signer('Ada', 'ada@example.com'), 'sha256' => $v1, 'signature_sha256' => $markA]),
    5 => $event(5, 'signer:2', 'signature.viewed', 'signing:'.$signing, ['signer' => $signer('Grace', 'Grace@Example.com'), 'sha256' => $v1]),
    6 => $event(6, 'signer:2', 'signature.signed', 'signing:'.$signing, ['signer' => $signer('Grace', 'Grace@Example.com'), 'sha256' => $v1, 'signature_sha256' => $markB]),
    7 => $event(7, 'sigilbase:signing', 'signature.request_completed', 'signing:'.$signing, ['sha256' => $v1]),
    8 => $event(8, 'user:owner', 'document.linked', 'document:msa', ['sha256' => $v1, 'target' => ['type' => 'event', 'sequence' => 2]]),
    9 => $event(9, 'user:owner', 'document.published', 'document:msa', ['document' => 'msa', 'version' => 2, 'sha256' => $v2, 'size_bytes' => 36]),
    10 => $event(10, 'user:owner', 'document.unlinked', 'document:msa', ['sha256' => $v1, 'target' => ['type' => 'event', 'sequence' => 2]]),
], $overrides);

$documents = static fn (): array => ['documents' => [[
    'slug' => 'msa',
    'title' => 'Master services agreement',
    'category' => 'contract',
    'resource' => 'document:msa',
    'versions' => [
        ['version' => 1, 'sha256' => $v1, 'size_bytes' => 36, 'origin' => 'uploaded', 'published_at' => $at(1), 'published_sequence' => 1],
        ['version' => 2, 'sha256' => $v2, 'size_bytes' => 36, 'origin' => 'uploaded', 'published_at' => $at(9), 'published_sequence' => 9],
    ],
]]];

$signatures = static fn (): array => ['signatures' => [[
    'id' => $signing,
    'document' => ['slug' => 'msa', 'version' => 1, 'sha256' => $v1],
    'order' => 'sequential',
    'status' => 'completed',
    'completed_at' => $at(7),
    'event_sequences' => [2, 3, 4, 5, 6, 7],
    'signers' => [
        ['position' => 1, 'name' => 'Ada', 'email' => 'ada@example.com', 'status' => 'signed', 'viewed_sha256' => $v1, 'signed_at' => $at(4), 'signature_sha256' => $markA, 'email_confirmed' => true],
        ['position' => 2, 'name' => 'Grace', 'email' => 'grace@example.com', 'status' => 'signed', 'viewed_sha256' => $v1, 'signed_at' => $at(6), 'signature_sha256' => $markB, 'email_confirmed' => true],
    ],
]]];

$links = static fn (): array => ['links' => [[
    'sha256' => $v1,
    'source_type' => 'document_version',
    'target' => ['type' => 'event', 'sequence' => 2],
    'linked_sequence' => 8,
    'unlinked_sequence' => 10,
    'active' => false,
]]];

$certificates = static fn (?string $file = null, ?string $sha = null): array => ['certificates' => [[
    'id' => $certificateId,
    'issued_at' => $at(11),
    'scope' => ['from' => 1, 'to' => 10],
    'file' => $file ?? 'certificates/'.$certificateId.'.pdf',
    'sha256' => $sha ?? hash('sha256', $certificate),
]]];

/**
 * @param  array<string, mixed>  $blocks  file name => decoded content (null leaves the file out)
 */
$build = static function (string $name, array $specs, array $blocks, array $manifest, bool $withCertificate = true, ?Closure $alter = null) use ($root, $seed, $stream, $work, $entries, $json, $certificate, $certificateId, &$changed): void {
    $generator = new FixtureGenerator($seed, $stream);
    $dir = $work.DIRECTORY_SEPARATOR.$name;
    $generator->writeStreamBundle($dir, array_values($specs), [
        'per_checkpoint' => 5,
        'format' => 'sigilbase-evidence/1.7',
        'stream' => ['slug' => 'contracts', 'name' => 'Contracts'],
        'manifest' => $manifest,
    ]);

    foreach ($blocks as $file => $content) {
        if ($content !== null) {
            file_put_contents($dir.DIRECTORY_SEPARATOR.$file, is_string($content) ? $content : $json($content));
        }
    }

    if ($alter !== null) {
        $alter($dir);
    }

    if ($withCertificate) {
        mkdir($dir.DIRECTORY_SEPARATOR.'certificates');
        file_put_contents($dir.DIRECTORY_SEPARATOR.'certificates'.DIRECTORY_SEPARATOR.$certificateId.'.pdf', $certificate);
    }

    $zip = $generator->zipAll($dir, $work.DIRECTORY_SEPARATOR.$name.'.zip');
    $target = $root.'/corpus/'.$name.'.zip';

    if ($entries($target) === $entries($zip)) {
        return;
    }

    copy($zip, $target);
    $changed = true;
    echo "wrote corpus/{$name}.zip\n";
};

$blocks = static fn (array $overrides = []): array => array_replace([
    'documents.json' => $documents(),
    'signatures.json' => $signatures(),
    'links.json' => $links(),
], $overrides);

$build('sigilsign', $history(), $blocks(), $certificates());

$wrongDocument = $documents();
$wrongDocument['documents'][0]['versions'][1]['sha256'] = $v1;
$build('sigilsign-document-sha', $history(), $blocks(['documents.json' => $wrongDocument]), $certificates());

$build('sigilsign-viewed-other', $history([
    5 => $event(5, 'signer:2', 'signature.viewed', 'signing:'.$signing, ['signer' => $signer('Grace', 'grace@example.com'), 'sha256' => $v2]),
]), $blocks(), $certificates());

$build('sigilsign-claimed-signer', $history([
    6 => $event(6, 'signer:2', 'signature.declined', 'signing:'.$signing, ['signer' => $signer('Grace', 'grace@example.com'), 'reason' => 'not mine to sign']),
]), $blocks(), $certificates());

$wrongMark = $signatures();
$wrongMark['signatures'][0]['signers'][0]['signature_sha256'] = $markB;
$build('sigilsign-signature-mark', $history(), $blocks(['signatures.json' => $wrongMark]), $certificates());

$unknownSigning = $signatures();
$unknownSigning['signatures'][0]['id'] = '019b7ca9-8c88-70c0-8000-00000000a0ff';
$build('sigilsign-no-signing-events', $history(), $blocks(['signatures.json' => $unknownSigning]), $certificates());

$wrongAction = $links();
$wrongAction['links'][0]['linked_sequence'] = 1;
$build('sigilsign-link-action', $history(), $blocks(['links.json' => $wrongAction]), $certificates());

$wrongLinkSha = $links();
$wrongLinkSha['links'][0]['sha256'] = $v2;
$build('sigilsign-link-sha', $history(), $blocks(['links.json' => $wrongLinkSha]), $certificates());

$build('sigilsign-malformed', $history(), $blocks(['documents.json' => ['documents' => ['msa' => $documents()['documents'][0]]]]), $certificates());

// Members whose names are integers ("7", "0") holding integers, at the top
// of every block, in each record, and in a version and a signer: the shape
// that stopped 1.8.0. They are fields the verifier does not know: ignored,
// and the bundle reads as sigilsign.zip does.
$numeric = static function (array $block, string $list): array {
    $block['7'] = 7;
    $block['0'] = ['0' => 'unknown', 'sequence' => 'not an integer', '7' => 7];
    $block[$list][0]['0'] = ['7' => 7];

    return $block;
};
$numericDocuments = $numeric($documents(), 'documents');
$numericDocuments['documents'][0]['versions'][0]['7'] = 7;
$numericSignatures = $numeric($signatures(), 'signatures');
$numericSignatures['signatures'][0]['signers'][0]['7'] = 7;
$build('sigilsign-numeric-members', $history(), $blocks([
    'documents.json' => $numericDocuments,
    'signatures.json' => $numericSignatures,
    'links.json' => $numeric($links(), 'links'),
]), $certificates());

// A seq that is not an integer: PHP would warn converting it to an array
// key, and with display_errors on that lands ahead of the --json document.
$build('sigilsign-float-seq', $history(), $blocks(), $certificates(), alter: static function (string $dir): void {
    $path = $dir.DIRECTORY_SEPARATOR.'events.ndjson';
    $lines = explode("\n", (string) file_get_contents($path));
    $lines[0] = str_replace('"seq":1,', '"seq":1.5,', $lines[0]);
    file_put_contents($path, implode("\n", $lines));
});

$build('certificate-sha', $history(), $blocks(), $certificates(sha: hash('sha256', 'some other certificate')));
$build('certificate-missing', $history(), $blocks(), $certificates(), withCertificate: false);
$build('certificate-unsafe-path', $history(), $blocks(), $certificates(file: 'certificates/../manifest.json'));

$iterator = new RecursiveIteratorIterator(
    new RecursiveDirectoryIterator($work, FilesystemIterator::SKIP_DOTS),
    RecursiveIteratorIterator::CHILD_FIRST,
);

foreach ($iterator as $item) {
    $item->isDir() ? rmdir($item->getPathname()) : unlink($item->getPathname());
}

rmdir($work);

echo $changed ? "sigilsign fixtures rebuilt.\n" : "sigilsign fixtures already up to date.\n";

exit($changed ? 1 : 0);
