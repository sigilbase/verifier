<?php

declare(strict_types=1);

/**
 * Builds the shape fixtures in corpus/: bundles that say exactly what
 * corpus/valid.zip says, written in a shape the format allows but the
 * generator never produces, so the reading rules in FORMAT.md ("Field
 * types") have committed inputs in both verifiers' differential runs:
 *
 *   shape-absent-null.zip     every event line omits its null resource field:
 *                             an absent field reads as null and hashes as null
 *   shape-unknown-field.zip   an event line and a checkpoint carry a field the
 *                             format does not name: unknown fields are ignored
 *
 * Both pass with the results of valid.zip. The mutation differential
 * relies on the same two rules when it decides whether a mutant that
 * passed still says what its seed fixture said.
 *
 * Run from the repository root:
 *
 *   php tools/build-corpus-shape.php
 *
 * Exits 1 when a fixture changed, 0 when they were already up to date, so a
 * CI check can hold the committed files to this script. Fixtures are
 * compared by the bytes of their entries, not of the archive.
 */
$root = dirname(__DIR__);

/**
 * @return array<string, string>
 */
$entries = static function (string $path): array {
    $zip = new ZipArchive;

    if (! is_file($path) || $zip->open($path) !== true) {
        return [];
    }

    $out = [];

    for ($i = 0; $i < $zip->numFiles; $i++) {
        $name = (string) $zip->getNameIndex($i);
        $out[$name] = (string) $zip->getFromIndex($i);
    }

    $zip->close();

    return $out;
};

/**
 * @param  array<string, string>  $files
 */
$write = static function (string $path, array $files): void {
    $zip = new ZipArchive;

    if ($zip->open($path, ZipArchive::CREATE | ZipArchive::OVERWRITE) !== true) {
        fwrite(STDERR, "cannot write {$path}\n");
        exit(2);
    }

    foreach ($files as $name => $content) {
        $zip->addFromString($name, $content);
        $zip->setMtimeName($name, 315532800);
    }

    $zip->close();
};

$valid = $entries($root.'/corpus/valid.zip');

if ($valid === [] || ! isset($valid['events.ndjson'], $valid['checkpoints.json'])) {
    fwrite(STDERR, "corpus/valid.zip is missing or incomplete\n");
    exit(2);
}

$fixtures = [];

// shape-absent-null: the generator writes "resource":null on every event;
// a producer that leaves null fields out writes the same record.
$absent = $valid;
$lines = explode("\n", $valid['events.ndjson']);
$removed = 0;

foreach ($lines as $i => $line) {
    $stripped = str_replace(',"resource":null', '', $line, $count);
    $removed += $count;
    $lines[$i] = $stripped;
}

if ($removed === 0) {
    fwrite(STDERR, "corpus/valid.zip has no null resource to omit\n");
    exit(2);
}

$absent['events.ndjson'] = implode("\n", $lines);
$fixtures['shape-absent-null'] = $absent;

// shape-unknown-field: a field the format does not name, on an event line
// and on a checkpoint, in sorted position so the line stays canonical.
$unknown = $valid;
$lines = explode("\n", $valid['events.ndjson']);
$lines[6] = str_replace('"payload":', '"note":"a field no check reads","payload":', $lines[6], $count);

if ($count !== 1) {
    fwrite(STDERR, "event line 7 of corpus/valid.zip has no payload field to anchor on\n");
    exit(2);
}

$unknown['events.ndjson'] = implode("\n", $lines);

$checkpoints = json_decode($valid['checkpoints.json'], true, 512, JSON_THROW_ON_ERROR);

if (! is_array($checkpoints) || ! isset($checkpoints['checkpoints'][0]) || ! is_array($checkpoints['checkpoints'][0])) {
    fwrite(STDERR, "corpus/valid.zip has no checkpoint to extend\n");
    exit(2);
}

$checkpoints['checkpoints'][0]['note'] = 'a field no check reads';
$unknown['checkpoints.json'] = json_encode($checkpoints, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR)."\n";
$fixtures['shape-unknown-field'] = $unknown;

$changed = false;

foreach ($fixtures as $name => $files) {
    $target = $root.'/corpus/'.$name.'.zip';

    if ($entries($target) === $files) {
        echo "unchanged  corpus/{$name}.zip\n";

        continue;
    }

    $write($target, $files);
    $changed = true;
    echo "written    corpus/{$name}.zip\n";
}

exit($changed ? 1 : 0);
