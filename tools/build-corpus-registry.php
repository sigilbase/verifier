<?php

declare(strict_types=1);

/**
 * Builds the receipt and registry fixtures in corpus/registry/ (format 1.7,
 * verifier 1.8) with tests/RegistryHistory.php under the published corpus
 * test key and the corpus receipt key:
 *
 *   <variant>-registry.zip, <variant>-log.zip   a registry and its decision log
 *   receipts/                  every receipt the valid history's submitters hold
 *   receipts-unlogged/         those plus one signed receipt the log does not hold
 *   receipts-later/            those plus one for a decision after the log's export
 *   receipt-keys.json          the corpus receipt key, active
 *   receipt-keys-retired.json  the same key, retired before the receipts were signed
 *   receipt-tampered.json      a valid receipt with its outcome changed after signing
 *
 * where <variant> is each of RegistryHistory::VARIANTS.
 *
 * Run from the repository root:
 *
 *   php tools/build-corpus-registry.php
 *
 * Exits 1 when a fixture changed, 0 when they were already up to date, so a
 * CI check can hold the committed files to this script. Archives are
 * compared by the bytes of their entries, not of the archive.
 */
require_once __DIR__.'/../vendor/autoload.php';

use Sigilbase\Verifier\Tests\FixtureGenerator;
use Sigilbase\Verifier\Tests\RegistryHistory;

$root = dirname(__DIR__);
$seed = '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60';
$target = $root.'/corpus/registry';

$work = sys_get_temp_dir().DIRECTORY_SEPARATOR.'sigilbase-corpus-registry-'.bin2hex(random_bytes(4));
mkdir($work, 0755, true);

if (! is_dir($target)) {
    mkdir($target, 0755, true);
}

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
        $out[(string) $zip->getNameIndex($i)] = (string) $zip->getFromIndex($i);
    }

    $zip->close();
    ksort($out);

    return $out;
};

$put = static function (string $name, string $contents) use ($target, &$changed): void {
    $path = $target.'/'.$name;

    if (! is_dir(dirname($path))) {
        mkdir(dirname($path), 0755, true);
    }

    if (is_file($path) && file_get_contents($path) === $contents) {
        return;
    }

    file_put_contents($path, $contents);
    $changed = true;
    echo "wrote corpus/registry/{$name}\n";
};

$json = static fn (mixed $value): string => json_encode($value, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR)."\n";

$receipts = [];

foreach (RegistryHistory::VARIANTS as $variant) {
    $dir = $work.DIRECTORY_SEPARATOR.$variant;
    $written = RegistryHistory::write($seed, $dir, $variant);

    if ($variant === 'valid') {
        $receipts = $written;
    }

    foreach (['registry', 'log'] as $part) {
        $zip = (new FixtureGenerator($seed))->zipAll($dir.DIRECTORY_SEPARATOR.$part, $work.DIRECTORY_SEPARATOR."{$variant}-{$part}.zip");
        $path = "{$target}/{$variant}-{$part}.zip";

        if ($entries($path) !== $entries($zip)) {
            copy($zip, $path);
            $changed = true;
            echo "wrote corpus/registry/{$variant}-{$part}.zip\n";
        }
    }
}

foreach ($receipts as $name => $receipt) {
    $put('receipts/'.$name, $json($receipt));
    $put('receipts-unlogged/'.$name, $json($receipt));
    $put('receipts-later/'.$name, $json($receipt));
}

// A receipt for a decision after the log's last record, at 11:20: made
// after the log's export, it cannot be checked yet.
$later = RegistryHistory::receipt((object) [
    'seq' => 14,
    'received_at' => '2026-07-01T11:25:00.000000Z',
    'payload' => (object) [
        'outcome' => 'refused_late',
        'commitment_key' => 'acme-q3',
        'request_digest' => 'sha256:'.hash('sha256', 'a submission after the export'),
        'digest_kind' => 'canonical',
        'credential' => RegistryHistory::FILER,
        'accepted' => null,
        'reasons' => [],
    ],
], RegistryHistory::policy()['hash']);
$put('receipts-later/14-refused_late.json', $json($later));

// A receipt Sigilbase signed for a decision its log does not hold: from
// 11:15, before the log's last record.
$unlogged = RegistryHistory::receipt((object) [
    'seq' => 14,
    'received_at' => '2026-07-01T11:15:00.000000Z',
    'payload' => (object) [
        'outcome' => 'refused_late',
        'commitment_key' => 'acme-q3',
        'request_digest' => 'sha256:'.hash('sha256', 'a submission the log omits'),
        'digest_kind' => 'canonical',
        'credential' => RegistryHistory::FILER,
        'accepted' => null,
        'reasons' => [],
    ],
], RegistryHistory::policy()['hash']);
$put('receipts-unlogged/14-refused_late.json', $json($unlogged));

$put('receipt-keys.json', $json(RegistryHistory::receiptKeys()));
$put('receipt-keys-retired.json', $json(RegistryHistory::receiptKeys('2026-07-01T09:00:00.000000Z')));

// The acceptance receipt, its outcome changed after signing.
$tampered = $receipts['04-accepted.json'];
$tampered['body'] = clone $tampered['body'];
$tampered['body']->outcome = 'replay';
$put('receipt-tampered.json', $json($tampered));

$iterator = new RecursiveIteratorIterator(
    new RecursiveDirectoryIterator($work, FilesystemIterator::SKIP_DOTS),
    RecursiveIteratorIterator::CHILD_FIRST,
);

foreach ($iterator as $item) {
    $item->isDir() ? rmdir($item->getPathname()) : unlink($item->getPathname());
}

rmdir($work);

echo $changed ? "registry fixtures rebuilt.\n" : "registry fixtures already up to date.\n";

exit($changed ? 1 : 0);
