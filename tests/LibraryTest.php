<?php

declare(strict_types=1);

namespace Sigilbase\Verifier\Tests;

use PHPUnit\Framework\TestCase;

/**
 * Unit tests of verify.php's building blocks, required as a library (the
 * CLI does not run when the file is required), plus the static conduct
 * checks: no network-capable construct may appear in the file, and the
 * documented extension budget must hold.
 */
final class LibraryTest extends TestCase
{
    public static function setUpBeforeClass(): void
    {
        require_once dirname(__DIR__).'/verify.php';
    }

    public function testUtf16beMatchesKnownVectors(): void
    {
        // ASCII, Latin-1 supplement, BMP, and an astral-plane surrogate pair.
        self::assertSame("\x00a", utf16be('a'));
        self::assertSame("\x00\xE9", utf16be('é'));
        self::assertSame("\x20\xAC", utf16be('€'));
        self::assertSame("\xD8\x34\xDD\x1E", utf16be('𝄞'));
        self::assertSame("\x00h\x00i", utf16be('hi'));
    }

    public function testCanonicalEncodingSortsKeysByUtf16CodeUnits(): void
    {
        // RFC 8785's own ordering example relies on UTF-16 code units:
        // '€' (20AC) sorts before '😀' (D83D DE00) which sorts before
        // 'ﬁ' (FB01)? No — FB01 > D83D as code units, so the surrogate
        // comes first. That inversion versus code POINT order is exactly
        // what a naive byte comparison of UTF-8 gets wrong.
        $encoded = canonical_encode((object) ['ﬁ' => 1, '😀' => 2, '€' => 3]);

        self::assertSame('{"€":3,"😀":2,"ﬁ":1}', $encoded);
    }

    public function testCanonicalEncodingKnownVector(): void
    {
        self::assertSame(
            '{"a":"x","b":[1,true,null]}',
            canonical_encode((object) ['b' => [1, true, null], 'a' => 'x']),
        );
    }

    public function testMerkleRootMatchesTheRfc6962ReferenceVector(): void
    {
        $leaves = array_map(
            static fn (string $hex): string => (string) hex2bin($hex),
            ['', '00', '10', '2021', '3031', '40414243', '5051525354555657', '606162636465666768696a6b6c6d6e6f'],
        );

        self::assertSame(
            '5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328',
            bin2hex(merkle_root($leaves)),
        );
    }

    public function testConsistencyProofRoundTripsAtEverySizePair(): void
    {
        $leaves = array_map(
            static fn (int $i): string => hash('sha256', "leaf-{$i}", true),
            range(1, 9),
        );

        for ($new = 1; $new <= 9; $new++) {
            $tree = array_slice($leaves, 0, $new);

            for ($old = 1; $old <= $new; $old++) {
                $proof = consistency_proof($tree, $old);

                self::assertTrue(consistency_verify(
                    $old,
                    $new,
                    merkle_root(array_slice($tree, 0, $old)),
                    merkle_root($tree),
                    $proof,
                ), "consistency failed for {$old} -> {$new}");
            }
        }
    }

    public function testTheVerifierContainsNoNetworkCapableConstruct(): void
    {
        $source = (string) file_get_contents(dirname(__DIR__).'/verify.php');

        $forbidden = [
            'curl_', 'fsockopen', 'pfsockopen', 'stream_socket_client', 'socket_create',
            "file_get_contents('http", 'file_get_contents("http',
            "fopen('http", 'fopen("http', 'get_headers', 'dns_get_record', 'gethostbyname',
        ];

        foreach ($forbidden as $needle) {
            self::assertStringNotContainsString($needle, $source, "verify.php must not contain [{$needle}]");
        }
    }

    public function testTheVerifierDoesNotRequireMbstringOrOtherOptionalExtensions(): void
    {
        $source = (string) file_get_contents(dirname(__DIR__).'/verify.php');

        foreach (['mb_', 'iconv', 'intl', 'gmp_', 'bcmath', 'bc'] as $needle) {
            self::assertDoesNotMatchRegularExpression(
                '/\b'.preg_quote($needle, '/').'\w*\s*\(/',
                $source,
                "verify.php must not call into the [{$needle}] extension",
            );
        }
    }
}
