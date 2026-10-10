<?php

declare(strict_types=1);

namespace Sigilbase\Verifier\Tests;

use PHPUnit\Framework\TestCase;

/**
 * The collection records of format 1.6 (FORMAT.md, "Collection records"):
 * a connection's receipt stream built event by event with the fixture
 * generator, then one rule broken at a time. Every bundle here is
 * signed and chained correctly; what the verifier must catch is a
 * receipt stream whose own statements contradict each other.
 */
final class CollectionRecordsTest extends TestCase
{
    private string $workDir;

    private FixtureGenerator $generator;

    protected function setUp(): void
    {
        $this->workDir = sys_get_temp_dir().DIRECTORY_SEPARATOR.'sigilbase-collection-test-'.bin2hex(random_bytes(6));
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

    // -- A valid receipt stream ------------------------------------------------

    public function testAValidReceiptStreamPassesAndIsSummarised(): void
    {
        $run = $this->verify($this->bundle(CollectionHistory::history()));

        self::assertSame(0, $run['code'], $run['stdout'].$run['stderr']);
        self::assertStringContainsString('Checking collection records', $run['stdout']);
        self::assertStringContainsString('stream records: 3 receipt(s) chained, 1 gap(s) declared, 3 settlement record(s)', $run['stdout']);
        self::assertStringContainsString('Collection records: 3 receipt(s) chained on 1 stream(s), 1 gap(s) declared, 3 settlement record(s)', $run['stdout']);
        self::assertStringContainsString('connection.json is absent', $run['stdout']);
    }

    public function testAValidReceiptStreamWithItsConnectionFilePassesWithoutTheAbsenceNote(): void
    {
        $run = $this->verify($this->bundle(CollectionHistory::history(), ['connection' => CollectionHistory::connectionJson()]));

        self::assertSame(0, $run['code'], $run['stdout'].$run['stderr']);
        self::assertStringNotContainsString('connection.json is absent', $run['stdout']);
    }

    public function testAFormat15BundleCarryingTheseEventsIsVerifiedAsEventsAlone(): void
    {
        $history = CollectionHistory::history();
        $history[2]['payload'] = CollectionHistory::with($history[2]['payload'], ['prev_receipt_hash' => CollectionHistory::ZERO]);

        $run = $this->verify($this->bundle($history, ['format' => 'sigilbase-evidence/1.5']));

        self::assertSame(0, $run['code'], $run['stdout'].$run['stderr']);
        self::assertStringNotContainsString('Checking collection records', $run['stdout']);
    }

    // -- Receipt chain ---------------------------------------------------------

    public function testABrokenReceiptLinkFails(): void
    {
        $history = CollectionHistory::history();
        $history[2]['payload'] = CollectionHistory::with($history[2]['payload'], ['prev_receipt_hash' => CollectionHistory::ZERO]);

        $this->assertFails($history, 'prev_receipt_hash does not name the previous receipt\'s entry hash');
    }

    public function testAReceiptIndexThatSkipsFails(): void
    {
        $history = CollectionHistory::history();
        $history[2]['payload'] = CollectionHistory::with($history[2]['payload'], ['receipt_index' => 3]);

        $this->assertFails($history, 'receipt_index 3 follows receipt 1');
    }

    public function testACursorThatDoesNotFollowFails(): void
    {
        $history = CollectionHistory::history();
        $history[2]['payload'] = CollectionHistory::with($history[2]['payload'], ['cursor_before' => (object) ['sequence' => 99]]);

        $this->assertFails($history, 'cursor_before does not equal the previous receipt\'s cursor_after');
    }

    public function testAFirstReceiptMustNameTheZeroHash(): void
    {
        $history = CollectionHistory::history();
        $history[1]['payload'] = CollectionHistory::with($history[1]['payload'], ['prev_receipt_hash' => str_repeat('a', 64)]);

        $this->assertFails($history, 'the first receipt of a stream must name the zero hash');
    }

    public function testAnUnknownReceiptVersionFails(): void
    {
        $history = CollectionHistory::history();
        $history[1]['payload'] = CollectionHistory::with($history[1]['payload'], ['receipt_version' => 2]);

        $this->assertFails($history, 'receipt_version is not 1');
    }

    public function testARecordCountBeyondItsRangeFails(): void
    {
        $history = CollectionHistory::history();
        $history[1]['payload'] = CollectionHistory::with($history[1]['payload'], ['record_count' => 9]);

        $this->assertFails($history, 'record_count 9 exceeds the records range');
    }

    // -- Gaps and settlement ---------------------------------------------------

    public function testAGapPlacedAfterTheWrongReceiptFails(): void
    {
        $history = CollectionHistory::history();
        $history[3]['payload'] = CollectionHistory::with($history[3]['payload'], ['declared_after_receipt_hash' => CollectionHistory::ZERO]);

        $this->assertFails($history, 'declared_after_receipt_hash does not name the latest receipt before it');
    }

    public function testASettlementNamingTheWrongReceiptHeadFails(): void
    {
        $history = CollectionHistory::history();
        $history[4]['payload'] = CollectionHistory::with($history[4]['payload'], ['receipts' => (object) ['count' => 2, 'last_receipt_hash' => CollectionHistory::ZERO]]);

        $this->assertFails($history, 'receipts.last_receipt_hash does not name the latest receipt before it');
    }

    public function testASettlementWhoseStateContradictsItsGapsFails(): void
    {
        $history = CollectionHistory::history();
        $history[5]['payload'] = CollectionHistory::with($history[5]['payload'], ['state' => 'settled']);

        $this->assertFails($history, 'state is settled but the listed gaps say gapped');
    }

    public function testASettlementListingAGapTheChainNeverDeclaredFails(): void
    {
        $history = CollectionHistory::history();
        $history[5]['payload'] = CollectionHistory::with($history[5]['payload'], ['gaps' => [
            ['gap_id' => 'gap-never', 'from' => '2026-07-02T09:00:00.000000Z', 'to' => '2026-07-02T10:00:00.000000Z', 'reason' => 'connection_paused', 'healed' => false],
        ]]);

        $this->assertFails($history, 'lists gap [gap-never], which the chain never declared');
    }

    public function testAHealNamingADeclaredGapLetsASupplementSettleTheDay(): void
    {
        $run = $this->verify($this->bundle(CollectionHistory::healed()));

        self::assertSame(0, $run['code'], $run['stdout'].$run['stderr']);
        self::assertStringContainsString('stream records: 4 receipt(s) chained, 1 gap(s) declared, 4 settlement record(s)', $run['stdout']);
    }

    public function testAHealNamingAGapTheChainNeverDeclaredFails(): void
    {
        $history = CollectionHistory::healed();
        $history[9]['payload'] = CollectionHistory::with($history[9]['payload'], ['gap_id' => 'gap-9']);
        // The supplement then says what the chain says: gap-1 unhealed, the day still gapped.
        $history[10]['payload'] = static fn (array $built): object => CollectionHistory::settled($built, '2026-07-02', 'gapped', [
            ['gap_id' => 'gap-1', 'from' => '2026-07-02T09:00:00.000000Z', 'to' => '2026-07-02T10:00:00.000000Z', 'reason' => 'connection_paused', 'healed' => false],
        ], 1, CollectionHistory::settlementOf($built, '2026-07-02'));

        $this->assertFails($history, 'heals gap [gap-9], which the chain never declared in a bundle that starts at sequence 1');
    }

    public function testASupplementStillSayingGappedAfterTheHealFails(): void
    {
        $history = CollectionHistory::healed();
        $history[10]['payload'] = CollectionHistory::with($history[10]['payload'], ['state' => 'gapped']);

        $this->assertFails($history, 'state is gapped but the listed gaps say settled');
    }

    public function testASupplementMustFollowTheSettlementItAddsTo(): void
    {
        $history = CollectionHistory::history();
        $history[7]['payload'] = CollectionHistory::with($history[7]['payload'], ['previous_settlement' => (object) ['sequence' => 5, 'entry_hash' => str_repeat('b', 64)]]);

        $this->assertFails($history, 'supplement 1 for day 2026-07-01 does not follow the previous settlement in the chain');
    }

    public function testADaySettledTwiceFails(): void
    {
        $history = CollectionHistory::history();
        $history[7]['payload'] = CollectionHistory::with($history[7]['payload'], ['supplement' => 0, 'previous_settlement' => null]);

        $this->assertFails($history, 'day 2026-07-01 was already settled at sequence 5');
    }

    public function testARecordBeforeTheConfigurationFailsInAnAnchoredBundle(): void
    {
        $history = CollectionHistory::history();
        [$history[0], $history[1]] = [$history[1], $history[0]];

        $this->assertFails($history, 'a collection record precedes the stream\'s configuration');
    }

    // -- Ranges and connection.json --------------------------------------------

    public function testABundleStartingLaterNotesTheLinksItCannotShowAndPasses(): void
    {
        // range_from 3 starts at the second receipt: its link to receipt 1
        // lies before the range.
        $run = $this->verify($this->bundle(CollectionHistory::history(), ['range_from' => 3]));

        self::assertSame(0, $run['code'], $run['stdout'].$run['stderr']);
        self::assertStringContainsString('the receipt chain enters this range at receipt 2; its link to receipt 1 lies before the range', $run['stdout']);
        self::assertStringContainsString('stream records: 2 receipt(s) chained, 1 gap(s) declared, 3 settlement record(s)', $run['stdout']);
    }

    public function testConnectionJsonThatContradictsTheChainFails(): void
    {
        $this->assertFails(
            CollectionHistory::history(),
            'connection.json names records stream [some-other-stream] for [records] but the chain\'s configuration names [payments-feed]',
            ['connection' => CollectionHistory::connectionJson('some-other-stream')],
        );

        $this->assertFails(
            CollectionHistory::history(),
            'connection.json lists stream [audit] but a bundle that starts at sequence 1 holds no configuration for it',
            ['connection' => ['role' => 'receipts', 'record_streams' => [['stream_key' => 'records', 'stream' => 'payments-feed'], ['stream_key' => 'audit', 'stream' => 'audit-feed']]]],
        );

        $this->assertFails(
            CollectionHistory::history(),
            'connection.json is present but malformed',
            ['connection' => ['role' => 'something-else']],
        );
    }

    public function testARecordsBundleIsNotedAndNotCheckedAsAChain(): void
    {
        $run = $this->verify($this->bundle([
            ['action' => 'payment.created', 'resource' => 'pay_1', 'payload' => (object) ['raw' => '{"id":"pay_1"}', 'raw_sha256' => hash('sha256', '{"id":"pay_1"}')]],
            ['action' => 'payment.created', 'resource' => 'pay_2', 'payload' => (object) ['raw' => '{"id":"pay_2"}', 'raw_sha256' => hash('sha256', '{"id":"pay_2"}')]],
        ], ['connection' => ['role' => 'records', 'receipt_stream' => 'sigilbase-connection-abc123def456']]));

        self::assertSame(0, $run['code'], $run['stdout'].$run['stderr']);
        self::assertStringContainsString('the receipts covering them are in stream [sigilbase-connection-abc123def456]', $run['stdout']);
        self::assertStringNotContainsString('Checking collection records', $run['stdout']);
    }

    public function testAReceiptsConnectionFileOverARangeWithNoRecordsFails(): void
    {
        $run = $this->verify($this->bundle([
            ['action' => 'payment.created', 'resource' => 'pay_1', 'payload' => (object) ['n' => 1]],
            ['action' => 'payment.created', 'resource' => 'pay_2', 'payload' => (object) ['n' => 2]],
        ], ['connection' => CollectionHistory::connectionJson()]));

        self::assertSame(1, $run['code'], $run['stdout'].$run['stderr']);
        self::assertStringContainsString('the range holds no collection record at all', $run['stdout']);
    }

    public function testJsonModeReportsTheFailureUnderContentIntegrity(): void
    {
        $history = CollectionHistory::history();
        $history[2]['payload'] = CollectionHistory::with($history[2]['payload'], ['prev_receipt_hash' => CollectionHistory::ZERO]);

        $run = $this->verify($this->bundle($history), ['--json']);
        $document = json_decode($run['stdout'], true);

        self::assertSame(1, $run['code']);
        self::assertSame('fail', $document['results']['content_integrity']);
        self::assertSame('pass', $document['results']['redactions']);
        self::assertNotEmpty(array_filter($document['failures'], static fn (string $failure): bool => str_contains($failure, 'receipt chain is broken')));
    }

    // -- Plumbing --------------------------------------------------------------

    /**
     * @param  list<array{action: string, resource: string|null, payload: object}>  $specs
     * @param  array<string, mixed>  $options
     */
    private function bundle(array $specs, array $options = []): string
    {
        static $counter = 0;

        return $this->generator->writeCollectionBundle($this->workDir.DIRECTORY_SEPARATOR.'bundle-'.(++$counter), $specs, $options);
    }

    /**
     * @param  list<array{action: string, resource: string|null, payload: object}>  $specs
     * @param  array<string, mixed>  $options
     */
    private function assertFails(array $specs, string $failure, array $options = []): void
    {
        $run = $this->verify($this->bundle($specs, $options));

        self::assertSame(1, $run['code'], $run['stdout'].$run['stderr']);
        self::assertStringContainsString($failure, $run['stdout']);
        self::assertStringContainsString('Content integrity  FAIL', $run['stdout']);
    }

    /**
     * @param  list<string>  $arguments
     * @return array{code: int, stdout: string, stderr: string}
     */
    private function verify(string $bundle, array $arguments = []): array
    {
        $command = escapeshellarg(PHP_BINARY).' '.escapeshellarg(dirname(__DIR__).'/verify.php')
            .' --keys '.escapeshellarg($this->trustedKeysFile());

        foreach ([...$arguments, $bundle] as $argument) {
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

    private function trustedKeysFile(): string
    {
        $path = $this->workDir.DIRECTORY_SEPARATOR.'trusted-keys.json';

        if (! is_file($path)) {
            file_put_contents($path, (string) json_encode(['keys' => [[
                'key_id' => substr(hash('sha256', (string) hex2bin($this->generator->publicKeyHex)), 0, 16),
                'public_key' => $this->generator->publicKeyHex,
                'algorithm' => 'ed25519',
                'created_at' => '2026-01-01T00:00:00.000000Z',
                'retired_at' => null,
            ]]], JSON_PRETTY_PRINT));
        }

        return $path;
    }
}
