<?php

declare(strict_types=1);

/**
 * Compiles keys/sigilbase.json into the TRUSTED_SIGNING_KEYS constant in
 * verify.php, and keys/tsa-roots.pem into TRUSTED_TSA_ROOTS.
 *
 * verify.php has to stay a single dependency-free file an auditor can
 * read end to end - it cannot load a JSON file that sits beside it,
 * because then the file beside it is part of the trust decision and a
 * bundle could ship one. So the release compiles the keys in, and a test
 * asserts the constant still equals the file.
 *
 * Run before tagging a release that changes either file:
 *
 *   php tools/compile-keys.php
 *
 * Exits 1 if verify.php changed, 0 if it was already up to date, so it
 * can gate a release.
 */
$root = dirname(__DIR__);
$verifyPath = $root.'/verify.php';

$source = file_get_contents($verifyPath);

if ($source === false) {
    fwrite(STDERR, "compile-keys: cannot read verify.php\n");
    exit(2);
}

$original = $source;

// ---- signing keys ---------------------------------------------------------

$keysPath = $root.'/keys/sigilbase.json';
$decoded = json_decode((string) file_get_contents($keysPath), true);

if (! is_array($decoded) || ! isset($decoded['keys']) || ! is_array($decoded['keys'])) {
    fwrite(STDERR, "compile-keys: keys/sigilbase.json has no keys array\n");
    exit(2);
}

$entries = [];

foreach ($decoded['keys'] as $key) {
    foreach (['key_id', 'public_key', 'algorithm', 'created_at'] as $field) {
        if (! array_key_exists($field, $key)) {
            fwrite(STDERR, "compile-keys: a key is missing [{$field}]\n");
            exit(2);
        }
    }

    // The id is a fingerprint anyone can recompute, so a mistyped one is
    // caught here rather than by someone wondering why two verifiers
    // disagree about which key signed something.
    $expected = substr(hash('sha256', (string) hex2bin($key['public_key'])), 0, 16);

    if ($key['key_id'] !== $expected) {
        fwrite(STDERR, "compile-keys: key_id [{$key['key_id']}] is not the fingerprint of its public key (expected {$expected})\n");
        exit(2);
    }

    $entries[] = sprintf(
        "    [\n        'key_id' => '%s',\n        'public_key' => '%s',\n        'algorithm' => '%s',\n        'created_at' => '%s',\n        'retired_at' => %s,\n    ],\n",
        $key['key_id'],
        $key['public_key'],
        $key['algorithm'],
        $key['created_at'],
        ($key['retired_at'] ?? null) === null ? 'null' : "'".$key['retired_at']."'",
    );
}

$source = replace_block($source, 'TRUSTED_SIGNING_KEYS', "const TRUSTED_SIGNING_KEYS = [\n".implode('', $entries).'];');

// ---- timestamp trust roots ------------------------------------------------

$rootsPath = $root.'/keys/tsa-roots.pem';
$roots = is_file($rootsPath) ? (string) file_get_contents($rootsPath) : '';

$source = replace_block(
    $source,
    'TRUSTED_TSA_ROOTS',
    "const TRUSTED_TSA_ROOTS = ".var_export($roots, true).';',
);

// ---- write ----------------------------------------------------------------

if ($source === $original) {
    echo "compile-keys: verify.php is already up to date.\n";
    exit(0);
}

file_put_contents($verifyPath, $source);

echo "compile-keys: rewrote the trusted sets in verify.php.\n";
echo 'compile-keys: verify.php sha256 is now '.hash_file('sha256', $verifyPath)."\n";

exit(1);

/**
 * Replace `const <name> = ...;` up to the first line that is exactly `];`
 * or the end of a single-line declaration.
 */
function replace_block(string $source, string $name, string $replacement): string
{
    $pattern = '/^const '.preg_quote($name, '/').' = (?:\[.*?^\];|.*?;)$/ms';

    if (preg_match($pattern, $source) !== 1) {
        fwrite(STDERR, "compile-keys: cannot find the {$name} declaration in verify.php\n");
        exit(2);
    }

    return (string) preg_replace($pattern, str_replace('$', '\\$', $replacement), $source, 1);
}
