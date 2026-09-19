<?php

declare(strict_types=1);

/**
 * Builds the consistency fixtures in corpus/ with tests/FixtureGenerator.php
 * under the published corpus test key (corpus/test-signing-key.txt) and a
 * fixed stream id, so that the two-bundle and recorded-root forms of
 * --consistency have committed, reproducible inputs:
 *
 *   consistency-old.zip        events 1..20
 *   consistency-new.zip        events 1..40, the same history extended
 *   consistency-rewritten.zip  events 1..40 with a different early history
 *
 * Run from the repository root:
 *
 *   php tools/build-corpus-consistency.php
 *
 * Exits 1 when a fixture changed, 0 when they were already up to date, so a
 * CI check can hold the committed files to this script. Fixtures are
 * compared by the bytes of their entries, not of the archive: the entry
 * contents are deterministic, the zip container's bytes depend on the
 * libzip and zlib that wrote it, and a committed archive is only replaced
 * when its contents differ.
 */
require_once __DIR__.'/../vendor/autoload.php';

use Sigilbase\Verifier\Tests\FixtureGenerator;

$root = dirname(__DIR__);
$seed = '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60';
$stream = '019b7ca9-8c88-70c0-8000-0000000000c0';

$work = sys_get_temp_dir().DIRECTORY_SEPARATOR.'sigilbase-corpus-consistency-'.bin2hex(random_bytes(4));
mkdir($work, 0755, true);

$changed = false;

/**
 * The entries of an archive, name => bytes, or null when it cannot be read.
 *
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

$build = static function (string $name, int $events, string $salt) use ($root, $seed, $stream, $work, $entries, &$changed): void {
    $generator = new FixtureGenerator($seed, $stream);
    $dir = $generator->writeBundle($work.DIRECTORY_SEPARATOR.$name, $events, 10, $salt);
    $zip = $generator->zip($dir, $work.DIRECTORY_SEPARATOR.$name.'.zip');

    $target = $root.'/corpus/'.$name.'.zip';

    if ($entries($target) === $entries($zip)) {
        return;
    }

    copy($zip, $target);
    $changed = true;
    echo "wrote corpus/{$name}.zip\n";
};

$build('consistency-old', 20, '');
$build('consistency-new', 40, '');
$build('consistency-rewritten', 40, '-rewritten');

$iterator = new RecursiveIteratorIterator(
    new RecursiveDirectoryIterator($work, FilesystemIterator::SKIP_DOTS),
    RecursiveIteratorIterator::CHILD_FIRST,
);

foreach ($iterator as $item) {
    $item->isDir() ? rmdir($item->getPathname()) : unlink($item->getPathname());
}

rmdir($work);

echo $changed ? "consistency fixtures rebuilt.\n" : "consistency fixtures already up to date.\n";

exit($changed ? 1 : 0);
