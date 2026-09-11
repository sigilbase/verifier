<?php

declare(strict_types=1);

namespace Sigilbase\Verifier\Tests;

use PHPUnit\Framework\TestCase;

/**
 * The trusted sets compiled into verify.php.
 *
 * verify.php has to stay a single dependency-free file an auditor can read
 * end to end. It cannot load keys/sigilbase.json at runtime, because then
 * the file beside it would be part of the trust decision and a bundle
 * could ship one. So tools/compile-keys.php writes the keys into the
 * constant, and this holds the constant to the file the release publishes
 * - otherwise "which keys does this verifier trust" would have two
 * answers, and the one people read would not be the one that decides.
 */
final class TrustedSetTest extends TestCase
{
    public static function setUpBeforeClass(): void
    {
        require_once dirname(__DIR__).'/verify.php';
    }

    public function testTheCompiledKeysEqualThePublishedFile(): void
    {
        $document = json_decode((string) file_get_contents(dirname(__DIR__).'/keys/sigilbase.json'), true);

        self::assertIsArray($document);
        self::assertArrayHasKey('keys', $document);

        $expected = array_map(static fn (array $key): array => [
            'key_id' => $key['key_id'],
            'public_key' => $key['public_key'],
            'algorithm' => $key['algorithm'],
            'created_at' => $key['created_at'],
            'retired_at' => $key['retired_at'] ?? null,
        ], $document['keys']);

        self::assertSame(
            $expected,
            TRUSTED_SIGNING_KEYS,
            'verify.php and keys/sigilbase.json disagree; run php tools/compile-keys.php',
        );
    }

    public function testEveryKeyIdIsTheFingerprintOfItsKey(): void
    {
        // The id is a fingerprint anyone can recompute from the key bytes,
        // not an identifier you would have to take our word for. A wrong
        // one would have two verifiers naming the same key differently.
        foreach (TRUSTED_SIGNING_KEYS as $key) {
            $raw = hex2bin($key['public_key']);

            self::assertIsString($raw, 'a trusted public key is not hex');
            self::assertSame(32, strlen($raw), 'a trusted public key is not 32 bytes');
            self::assertSame(substr(hash('sha256', $raw), 0, 16), $key['key_id']);
            self::assertSame('ed25519', $key['algorithm']);
        }
    }

    public function testTheCompiledTsaRootsEqualThePublishedFile(): void
    {
        $path = dirname(__DIR__).'/keys/tsa-roots.pem';
        $expected = is_file($path) ? (string) file_get_contents($path) : '';

        self::assertSame(
            $expected,
            TRUSTED_TSA_ROOTS,
            'verify.php and keys/tsa-roots.pem disagree; run php tools/compile-keys.php',
        );
    }

    public function testTheTrustedSetHoldsNoPrivateMaterial(): void
    {
        // A 32-byte public key is 64 hex characters. An Ed25519 secret key
        // is 64 bytes; anything that long in this file would be a
        // catastrophe worth failing a build over.
        $source = (string) file_get_contents(dirname(__DIR__).'/verify.php');

        self::assertSame(
            0,
            preg_match('/\b[0-9a-f]{128}\b/', $source),
            'verify.php contains a 64-byte hex string, which is the shape of an Ed25519 secret key',
        );
    }
}
