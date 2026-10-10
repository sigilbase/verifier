<?php

declare(strict_types=1);

/**
 * Builds the collection-record fixtures in corpus/ (format 1.6) with
 * tests/FixtureGenerator.php and tests/CollectionHistory.php under the
 * published corpus test key and a fixed stream id, so the receipt chain,
 * gap and settlement rules have committed, reproducible inputs in both
 * verifiers' differential runs:
 *
 *   collection-receipts.zip          a consistent receipt stream, with connection.json
 *   collection-receipts-partial.zip  the same from sequence 3: links before the range are noted
 *   collection-receipt-link.zip      a receipt naming the wrong previous receipt
 *   collection-settled-head.zip      a settlement naming the wrong receipt head
 *   collection-gapped-state.zip      a settlement saying settled over an unhealed gap
 *   collection-connection-json.zip   connection.json contradicting the chain's configuration
 *   collection-format-1-5.zip        the broken link at format 1.5: verified as events alone
 *   collection-gap-healed.zip        a backfill receipt, the heal of gap-1 and the supplement settling its day
 *   collection-heal-unknown-gap.zip  a heal naming a gap the chain never declared
 *   collection-healed-state.zip      a supplement still saying gapped after the heal
 *
 * Run from the repository root:
 *
 *   php tools/build-corpus-collection.php
 *
 * Exits 1 when a fixture changed, 0 when they were already up to date, so a
 * CI check can hold the committed files to this script. Fixtures are
 * compared by the bytes of their entries, not of the archive.
 */
require_once __DIR__.'/../vendor/autoload.php';

use Sigilbase\Verifier\Tests\CollectionHistory;
use Sigilbase\Verifier\Tests\FixtureGenerator;

$root = dirname(__DIR__);
$seed = '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60';
$stream = '019b7ca9-8c88-70c0-8000-0000000000c6';

$work = sys_get_temp_dir().DIRECTORY_SEPARATOR.'sigilbase-corpus-collection-'.bin2hex(random_bytes(4));
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

/**
 * @param  list<array{action: string, resource: string|null, payload: object|Closure}>  $specs
 * @param  array<string, mixed>  $options
 */
$build = static function (string $name, array $specs, array $options) use ($root, $seed, $stream, $work, $entries, &$changed): void {
    $generator = new FixtureGenerator($seed, $stream);
    $dir = $generator->writeCollectionBundle($work.DIRECTORY_SEPARATOR.$name, $specs, $options);
    $zip = $generator->zipAll($dir, $work.DIRECTORY_SEPARATOR.$name.'.zip');

    $target = $root.'/corpus/'.$name.'.zip';

    if ($entries($target) === $entries($zip)) {
        return;
    }

    copy($zip, $target);
    $changed = true;
    echo "wrote corpus/{$name}.zip\n";
};

$history = CollectionHistory::history();
$connection = CollectionHistory::connectionJson();

$build('collection-receipts', $history, ['connection' => $connection]);
$build('collection-receipts-partial', $history, ['connection' => $connection, 'range_from' => 3]);

$brokenLink = $history;
$brokenLink[2]['payload'] = CollectionHistory::with($brokenLink[2]['payload'], ['prev_receipt_hash' => CollectionHistory::ZERO]);
$build('collection-receipt-link', $brokenLink, ['connection' => $connection]);
$build('collection-format-1-5', $brokenLink, ['connection' => $connection, 'format' => 'sigilbase-evidence/1.5']);

$wrongHead = $history;
$wrongHead[4]['payload'] = CollectionHistory::with($wrongHead[4]['payload'], ['receipts' => (object) ['count' => 2, 'last_receipt_hash' => CollectionHistory::ZERO]]);
$build('collection-settled-head', $wrongHead, ['connection' => $connection]);

$wrongState = $history;
$wrongState[5]['payload'] = CollectionHistory::with($wrongState[5]['payload'], ['state' => 'settled']);
$build('collection-gapped-state', $wrongState, ['connection' => $connection]);

$build('collection-connection-json', $history, ['connection' => CollectionHistory::connectionJson('some-other-stream')]);

// The history continued by a healing backfill, and the two ways a heal can
// be contradicted: by naming a gap never declared, and by a supplement that
// does not take it into account.
$healed = CollectionHistory::healed();
$build('collection-gap-healed', $healed, ['connection' => $connection]);

$unknownHeal = CollectionHistory::healed();
$unknownHeal[9]['payload'] = CollectionHistory::with($unknownHeal[9]['payload'], ['gap_id' => 'gap-9']);
$unknownHeal[10]['payload'] = static fn (array $built): object => CollectionHistory::settled($built, '2026-07-02', 'gapped', [
    ['gap_id' => 'gap-1', 'from' => '2026-07-02T09:00:00.000000Z', 'to' => '2026-07-02T10:00:00.000000Z', 'reason' => 'connection_paused', 'healed' => false],
], 1, CollectionHistory::settlementOf($built, '2026-07-02'));
$build('collection-heal-unknown-gap', $unknownHeal, ['connection' => $connection]);

$staleState = CollectionHistory::healed();
$staleState[10]['payload'] = CollectionHistory::with($staleState[10]['payload'], ['state' => 'gapped']);
$build('collection-healed-state', $staleState, ['connection' => $connection]);

$iterator = new RecursiveIteratorIterator(
    new RecursiveDirectoryIterator($work, FilesystemIterator::SKIP_DOTS),
    RecursiveIteratorIterator::CHILD_FIRST,
);

foreach ($iterator as $item) {
    $item->isDir() ? rmdir($item->getPathname()) : unlink($item->getPathname());
}

rmdir($work);

echo $changed ? "collection fixtures rebuilt.\n" : "collection fixtures already up to date.\n";

exit($changed ? 1 : 0);
