<?php

declare(strict_types=1);

namespace Sigilbase\Verifier\Tests;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The SigilSign and Certificate of Evidence fixtures of corpus/ (built by
 * tools/build-corpus-sigilsign.php), run through verify.php exactly as
 * corpus/expected.json records them, which is what the Go implementation
 * is held to in the differential run. Each failing fixture fails on the
 * fact it contradicts and nothing else, and every run is made with every
 * PHP diagnostic displayed: a warning on hostile input would break the
 * --json document or reach stderr, and fails the case.
 */
final class SigilSignCorpusTest extends TestCase
{
    /**
     * Each failing fixture's failures, in order, by a phrase each carries. A
     * link stating the wrong hash fails at both its linked and unlinked
     * events; the float seq breaks the chain, and with it the publication
     * documents.json names.
     */
    private const FAILURES = [
        'sigilsign-document-sha' => ['documents.json: document msa states sha256'],
        'sigilsign-viewed-other' => ['the viewed and signed versions must be the same'],
        'sigilsign-claimed-signer' => ['the record claims grace@example.com signed but no signature.signed event'],
        'sigilsign-signature-mark' => ["ada@example.com's stated signature-mark hash does not match"],
        'sigilsign-no-signing-events' => ['has no events in this bundle'],
        'sigilsign-link-action' => ['linked_sequence 1 does not resolve to a document.linked event'],
        'sigilsign-link-sha' => ['but the document.linked event at sequence 8 carries', 'but the document.unlinked event at sequence 10 carries'],
        'sigilsign-malformed' => ['documents.json is present but malformed'],
        'sigilsign-float-seq' => ['an event is missing its sequence number', 'expected sequence 1 here', 'prev_hash does not match', 'event 5 is missing', 'document msa points at sequence 1, which is not in this bundle'],
        'certificate-sha' => ['the file does not match its manifest sha256'],
        'certificate-missing' => ['listed in the manifest but missing from the bundle'],
        'certificate-unsafe-path' => ['the manifest entry has a missing or unsafe file path'],
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

        $failures = array_map(
            static fn (mixed $failure): string => is_string($failure) ? $failure : (string) json_encode($failure),
            $document['failures'],
        );
        $phrases = self::FAILURES[$name] ?? [];

        self::assertCount(count($phrases), $failures, implode("\n", $failures));

        foreach ($phrases as $index => $phrase) {
            self::assertStringContainsString($phrase, $failures[$index]);
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
        // Every diagnostic displayed, whatever php.ini says. stderr goes to a
        // file, so neither pipe can fill while the other is read.
        $stderrPath = (string) tempnam(sys_get_temp_dir(), 'sigilbase-stderr-');
        $command = array_merge([PHP_BINARY, '-d', 'display_errors=1', '-d', 'error_reporting=-1', 'verify.php', '--json'], $arguments);
        $process = proc_open($command, [1 => ['pipe', 'w'], 2 => ['file', $stderrPath, 'w']], $pipes, dirname(__DIR__));

        self::assertIsResource($process);

        $stdout = (string) stream_get_contents($pipes[1]);
        fclose($pipes[1]);
        proc_close($process);

        $stderr = (string) file_get_contents($stderrPath);
        unlink($stderrPath);

        self::assertSame('', $stderr);

        $document = json_decode($stdout, true);

        self::assertIsArray($document, "no JSON document from verify.php:\n{$stdout}");

        return $document;
    }
}
