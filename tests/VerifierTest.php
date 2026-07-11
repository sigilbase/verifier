<?php

declare(strict_types=1);

namespace Sigilbase\Verifier\Tests;

use PHPUnit\Framework\TestCase;
use ZipArchive;

/**
 * End-to-end tests of verify.php as an auditor runs it: a subprocess per
 * invocation, asserting the exit code and the named failure. The bundles
 * come from FixtureGenerator; each tamper case mirrors an attack the
 * format defends against.
 */
final class VerifierTest extends TestCase
{
    private string $workDir;

    private FixtureGenerator $generator;

    protected function setUp(): void
    {
        $this->workDir = sys_get_temp_dir().DIRECTORY_SEPARATOR.'sigilbase-verify-test-'.bin2hex(random_bytes(6));
        mkdir($this->workDir, 0755, true);

        $this->generator = new FixtureGenerator;
    }

    protected function tearDown(): void
    {
        $iterator = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($this->workDir, \FilesystemIterator::SKIP_DOTS),
            \RecursiveIteratorIterator::CHILD_FIRST,
        );

        foreach ($iterator as $item) {
            $item->isDir() ? rmdir($item->getPathname()) : unlink($item->getPathname());
        }

        rmdir($this->workDir);
    }

    /**
     * @param  list<string>  $arguments
     * @return array{code: int, stdout: string, stderr: string}
     */
    private function runVerifier(array $arguments): array
    {
        $command = escapeshellarg(PHP_BINARY).' '.escapeshellarg(dirname(__DIR__).'/verify.php');

        foreach ($arguments as $argument) {
            $command .= ' '.escapeshellarg($argument);
        }

        $process = proc_open($command, [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);

        self::assertIsResource($process);

        $stdout = (string) stream_get_contents($pipes[1]);
        $stderr = (string) stream_get_contents($pipes[2]);

        fclose($pipes[1]);
        fclose($pipes[2]);

        return ['code' => proc_close($process), 'stdout' => $stdout, 'stderr' => $stderr];
    }

    private function bundleDir(): string
    {
        return $this->generator->writeBundle($this->workDir.DIRECTORY_SEPARATOR.'bundle');
    }

    // -- The happy path -------------------------------------------------------

    public function testAGenuineBundleDirectoryPasses(): void
    {
        $run = $this->runVerifier([$this->bundleDir()]);

        self::assertSame(0, $run['code'], $run['stdout'].$run['stderr']);
        self::assertStringContainsString('PASS', $run['stdout']);
        self::assertStringContainsString('Consistency state: tree_size=4 root=', $run['stdout']);
    }

    public function testAGenuineBundleZipPasses(): void
    {
        if (! class_exists(ZipArchive::class)) {
            self::markTestSkipped('ext-zip is not available.');
        }

        $zip = $this->generator->zip($this->bundleDir(), $this->workDir.DIRECTORY_SEPARATOR.'bundle.zip');

        $run = $this->runVerifier([$zip]);

        self::assertSame(0, $run['code'], $run['stdout'].$run['stderr']);
        self::assertStringContainsString('PASS', $run['stdout']);
    }

    // -- Tamper fixtures ------------------------------------------------------

    public function testAModifiedPayloadFailsNamingTheSequence(): void
    {
        $dir = $this->bundleDir();
        $path = $dir.DIRECTORY_SEPARATOR.'events.ndjson';

        $lines = explode("\n", trim((string) file_get_contents($path)));
        $lines[1] = str_replace('"n":2', '"n":9', $lines[1]);
        file_put_contents($path, implode("\n", $lines)."\n");

        $run = $this->runVerifier([$dir]);

        self::assertSame(1, $run['code']);
        self::assertStringContainsString('sequence 2', $run['stdout']);
        self::assertStringContainsString('payload_hash does not match', $run['stdout']);
    }

    public function testADeletedEventFailsNamingTheGap(): void
    {
        $dir = $this->bundleDir();
        $path = $dir.DIRECTORY_SEPARATOR.'events.ndjson';

        $lines = explode("\n", trim((string) file_get_contents($path)));
        unset($lines[1]);
        file_put_contents($path, implode("\n", array_values($lines))."\n");

        $run = $this->runVerifier([$dir]);

        self::assertSame(1, $run['code']);
        self::assertStringContainsString('expected sequence 2', $run['stdout']);
        self::assertStringContainsString('deleted, inserted, or reordered', $run['stdout']);
    }

    public function testReorderedEventsFail(): void
    {
        $dir = $this->bundleDir();
        $path = $dir.DIRECTORY_SEPARATOR.'events.ndjson';

        $lines = explode("\n", trim((string) file_get_contents($path)));
        [$lines[1], $lines[2]] = [$lines[2], $lines[1]];
        file_put_contents($path, implode("\n", $lines)."\n");

        $run = $this->runVerifier([$dir]);

        self::assertSame(1, $run['code']);
        self::assertStringContainsString('FAIL', $run['stdout']);
    }

    public function testAForgedCheckpointSignatureFailsNamingTheCheckpoint(): void
    {
        $dir = $this->bundleDir();
        $path = $dir.DIRECTORY_SEPARATOR.'checkpoints.json';

        $document = json_decode((string) file_get_contents($path));
        $document->checkpoints[0]->signature = str_repeat('ab', 64);
        file_put_contents($path, json_encode($document, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));

        $run = $this->runVerifier([$dir]);

        self::assertSame(1, $run['code']);
        self::assertStringContainsString('checkpoint 1..2', $run['stdout']);
        self::assertStringContainsString('signature does not verify', $run['stdout']);
    }

    public function testABrokenCheckpointChainFails(): void
    {
        $dir = $this->bundleDir();
        $path = $dir.DIRECTORY_SEPARATOR.'checkpoints.json';

        $document = json_decode((string) file_get_contents($path));
        $document->checkpoints = [$document->checkpoints[1]];
        file_put_contents($path, json_encode($document, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));

        $run = $this->runVerifier([$dir]);

        self::assertSame(1, $run['code']);
        self::assertStringContainsString('checkpoint', $run['stdout']);
    }

    public function testAMissingBundleFileFailsWithExitOne(): void
    {
        // Missing pieces are indistinguishable from deletion: exit 1, not 2.
        $dir = $this->bundleDir();
        unlink($dir.DIRECTORY_SEPARATOR.'events.ndjson');

        $run = $this->runVerifier([$dir]);

        self::assertSame(1, $run['code']);
        self::assertStringContainsString('missing', $run['stderr']);
    }

    // -- Exit code 2: usage and format errors ----------------------------------

    public function testAnUnknownFormatIdExitsTwo(): void
    {
        $dir = $this->bundleDir();
        $path = $dir.DIRECTORY_SEPARATOR.'manifest.json';

        $manifest = json_decode((string) file_get_contents($path));
        $manifest->format = 'sigilbase-evidence/999';
        file_put_contents($path, json_encode($manifest, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));

        $run = $this->runVerifier([$dir]);

        self::assertSame(2, $run['code']);
        self::assertStringContainsString('unknown format', $run['stderr']);
    }

    public function testNoArgumentsExitsTwoWithUsage(): void
    {
        $run = $this->runVerifier([]);

        self::assertSame(2, $run['code']);
        self::assertStringContainsString('usage:', $run['stderr']);
    }

    public function testANonexistentPathExitsTwo(): void
    {
        $run = $this->runVerifier([$this->workDir.DIRECTORY_SEPARATOR.'no-such-bundle.zip']);

        self::assertSame(2, $run['code']);
        self::assertStringContainsString('does not exist', $run['stderr']);
    }

    public function testAnUnknownOptionExitsTwo(): void
    {
        $run = $this->runVerifier(['--frobnicate', $this->bundleDir()]);

        self::assertSame(2, $run['code']);
        self::assertStringContainsString('unknown option', $run['stderr']);
    }

    // -- Flags ------------------------------------------------------------------

    public function testJsonModeEmitsOneParsableDocument(): void
    {
        $run = $this->runVerifier(['--json', $this->bundleDir()]);

        self::assertSame(0, $run['code']);

        $document = json_decode($run['stdout'], true);

        self::assertIsArray($document);
        self::assertSame('pass', $document['result']);
        self::assertSame('verify', $document['mode']);
        self::assertNotSame('', (string) $document['verifier_version']);
        self::assertSame(['from' => 1, 'to' => 4], $document['bundle']['range']);
        self::assertSame([], $document['failures']);
        self::assertSame(4, $document['consistency_state']['tree_size']);
    }

    public function testJsonModeReportsFailuresOnATamperedBundle(): void
    {
        $dir = $this->bundleDir();
        $path = $dir.DIRECTORY_SEPARATOR.'events.ndjson';

        $lines = explode("\n", trim((string) file_get_contents($path)));
        $lines[0] = str_replace('"n":1', '"n":7', $lines[0]);
        file_put_contents($path, implode("\n", $lines)."\n");

        $run = $this->runVerifier(['--json', $dir]);

        self::assertSame(1, $run['code']);

        $document = json_decode($run['stdout'], true);

        self::assertSame('fail', $document['result']);
        self::assertNotEmpty($document['failures']);
        self::assertStringContainsString('payload_hash', implode(' ', $document['failures']));
    }

    public function testQuietModeIsExitCodeOnly(): void
    {
        $pass = $this->runVerifier(['--quiet', $this->bundleDir()]);

        self::assertSame(0, $pass['code']);
        self::assertSame('', $pass['stdout']);
        self::assertSame('', $pass['stderr']);

        $missing = $this->runVerifier(['--quiet', $this->workDir.DIRECTORY_SEPARATOR.'absent.zip']);

        self::assertSame(2, $missing['code']);
        self::assertSame('', $missing['stdout']);
        self::assertSame('', $missing['stderr']);
    }

    public function testPrintHashesReportsVerifierAndBundleHashes(): void
    {
        if (! class_exists(ZipArchive::class)) {
            self::markTestSkipped('ext-zip is not available.');
        }

        $zip = $this->generator->zip($this->bundleDir(), $this->workDir.DIRECTORY_SEPARATOR.'bundle.zip');

        $run = $this->runVerifier(['--print-hashes', $zip]);

        self::assertSame(0, $run['code']);
        self::assertStringContainsString(
            'Verifier sha256: '.hash_file('sha256', dirname(__DIR__).'/verify.php'),
            $run['stdout'],
        );
        self::assertStringContainsString('Bundle sha256:  '.hash_file('sha256', $zip), $run['stdout']);
    }

    // -- Consistency mode ---------------------------------------------------------

    public function testConsistencyBetweenTwoExportsOfTheSameStream(): void
    {
        $old = $this->generator->writeBundle($this->workDir.DIRECTORY_SEPARATOR.'old', eventCount: 2);
        $new = $this->generator->writeBundle($this->workDir.DIRECTORY_SEPARATOR.'new', eventCount: 4);

        $run = $this->runVerifier(['--consistency', $old, $new]);

        self::assertSame(0, $run['code'], $run['stdout'].$run['stderr']);
        self::assertStringContainsString('append-only extension of the old bundle', $run['stdout']);
    }

    public function testConsistencyRejectsARewrittenHistory(): void
    {
        // The same stream, but the "new" export's early events carry
        // different content: a rewritten past. Both bundles verify on their
        // own — only the cross-export consistency check can catch this.
        $old = $this->generator->writeBundle($this->workDir.DIRECTORY_SEPARATOR.'old', eventCount: 2);
        $new = $this->generator->writeBundle($this->workDir.DIRECTORY_SEPARATOR.'new', eventCount: 4, payloadSalt: '-rewritten');

        $run = $this->runVerifier(['--consistency', $old, $new]);

        self::assertSame(1, $run['code']);
        self::assertStringContainsString('does NOT extend the old one', $run['stdout']);
    }

    public function testConsistencyRejectsBundlesFromDifferentStreams(): void
    {
        $old = $this->generator->writeBundle($this->workDir.DIRECTORY_SEPARATOR.'old', eventCount: 2);
        $new = (new FixtureGenerator)->writeBundle($this->workDir.DIRECTORY_SEPARATOR.'new', eventCount: 4);

        $run = $this->runVerifier(['--consistency', $old, $new]);

        self::assertSame(1, $run['code']);
        self::assertStringContainsString('different streams', $run['stdout']);
    }

    public function testConsistencyAgainstARecordedRoot(): void
    {
        $old = $this->generator->writeBundle($this->workDir.DIRECTORY_SEPARATOR.'old', eventCount: 2);
        $new = $this->generator->writeBundle($this->workDir.DIRECTORY_SEPARATOR.'new', eventCount: 4);

        $oldRun = $this->runVerifier([$old]);

        self::assertSame(1, preg_match('/tree_size=(\d+) root=([0-9a-f]{64})/', $oldRun['stdout'], $recorded));

        $pass = $this->runVerifier(['--consistency', $new, '--root', $recorded[2], '--size', $recorded[1]]);

        self::assertSame(0, $pass['code'], $pass['stdout']);
        self::assertStringContainsString('append-only extension of the recorded state', $pass['stdout']);

        $fail = $this->runVerifier(['--consistency', $new, '--root', str_repeat('ab', 32), '--size', $recorded[1]]);

        self::assertSame(1, $fail['code']);
        self::assertStringContainsString('does NOT extend the recorded state', $fail['stdout']);
    }
}
