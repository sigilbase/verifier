<?php

declare(strict_types=1);

namespace Sigilbase\Verifier\Tests;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The SigilSign and Certificate of Evidence fixtures of corpus/ (built by
 * tools/build-corpus-sigilsign.php), run through verify.php exactly as
 * corpus/expected.json records them, which is what the Go implementation
 * is held to in the differential run. Each failing fixture fails on the one
 * fact it contradicts, and the bundle stays verified in every other respect.
 */
final class SigilSignCorpusTest extends TestCase
{
    private const FAILURES = [
        'sigilsign-document-sha' => 'documents.json: document msa states sha256',
        'sigilsign-viewed-other' => 'the viewed and signed versions must be the same',
        'sigilsign-claimed-signer' => 'the record claims grace@example.com signed but no signature.signed event',
        'sigilsign-signature-mark' => "ada@example.com's stated signature-mark hash does not match",
        'sigilsign-no-signing-events' => 'has no events in this bundle',
        'sigilsign-link-action' => 'linked_sequence 1 does not resolve to a document.linked event',
        'sigilsign-link-sha' => 'but the document.linked event at sequence 8 carries',
        'sigilsign-malformed' => 'documents.json is present but malformed',
        'certificate-sha' => 'the file does not match its manifest sha256',
        'certificate-missing' => 'listed in the manifest but missing from the bundle',
        'certificate-unsafe-path' => 'the manifest entry has a missing or unsafe file path',
    ];

    /**
     * @return array<string, mixed>
     */
    private static function expected(): array
    {
        return json_decode((string) file_get_contents(dirname(__DIR__).'/corpus/expected.json'), true, flags: JSON_THROW_ON_ERROR);
    }

    /**
     * @return array<string, array{0: string, 1: list<string>, 2: array<string, mixed>}>
     */
    public static function fixtures(): array
    {
        $expected = self::expected();
        $cases = [];

        foreach ($expected['fixtures'] as $name => $case) {
            if (str_starts_with($name, 'sigilsign') || str_starts_with($name, 'certificate-')) {
                $cases[$name] = [$name, [...$expected['default_options'], "corpus/{$name}.zip"], $case];
            }
        }

        return $cases;
    }

    public function testEveryFixtureHasACase(): void
    {
        self::assertCount(count(self::FAILURES) + 2, self::fixtures());
    }

    /**
     * @param  list<string>  $arguments
     * @param  array<string, mixed>  $case
     */
    #[DataProvider('fixtures')]
    public function testEveryFixtureGivesItsRecordedVerdict(string $name, array $arguments, array $case): void
    {
        $document = $this->verify($arguments);

        self::assertSame($case['exit'], $document['exit_code']);
        self::assertSame($case['result'], $document['result']);
        self::assertSame($case['results'], $document['results']);

        $failures = implode("\n", array_map(
            static fn (mixed $failure): string => is_string($failure) ? $failure : (string) json_encode($failure),
            $document['failures'],
        ));

        if (isset(self::FAILURES[$name])) {
            self::assertStringContainsString(self::FAILURES[$name], $failures);
        } else {
            self::assertSame('', $failures);
        }
    }

    public function testMembersNamedWithIntegersAreIgnoredLikeAnyUnknownField(): void
    {
        $expected = self::expected();
        $plain = $this->verify([...$expected['default_options'], 'corpus/sigilsign.zip']);
        $numeric = $this->verify([...$expected['default_options'], 'corpus/sigilsign-numeric-members.zip']);

        self::assertSame(0, $numeric['exit_code']);
        self::assertSame($plain['results'], $numeric['results']);
        self::assertSame(
            array_values(array_filter($plain['notes'], static fn (mixed $note): bool => is_string($note) && preg_match('/^(documents|signatures|links)\.json/', $note) === 1)),
            array_values(array_filter($numeric['notes'], static fn (mixed $note): bool => is_string($note) && preg_match('/^(documents|signatures|links)\.json/', $note) === 1)),
        );
    }

    /**
     * @param  list<string>  $arguments
     * @return array<string, mixed>
     */
    private function verify(array $arguments): array
    {
        $command = array_merge([PHP_BINARY, 'verify.php', '--json'], $arguments);
        $process = proc_open($command, [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes, dirname(__DIR__));

        self::assertIsResource($process);

        $stdout = (string) stream_get_contents($pipes[1]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        proc_close($process);

        $document = json_decode($stdout, true);

        self::assertIsArray($document, "no JSON document from verify.php:\n{$stdout}");

        return $document;
    }
}
