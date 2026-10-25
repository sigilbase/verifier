<?php

declare(strict_types=1);

namespace Sigilbase\Verifier\Tests;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The receipt and registry fixtures of corpus/registry/ (FORMAT.md,
 * "Receipts and registries"), run through verify.php exactly as
 * corpus/expected.json records them, which is what the Go implementation
 * is held to in the differential run. Each case asserts the exit code, the
 * five results and the reason code of the first failed check.
 */
final class RegistryCorpusTest extends TestCase
{
    /**
     * @return array<string, mixed>
     */
    private static function expected(): array
    {
        return json_decode((string) file_get_contents(dirname(__DIR__).'/corpus/expected.json'), true, flags: JSON_THROW_ON_ERROR);
    }

    /**
     * @return array<string, array{0: list<string>, 1: array<string, mixed>}>
     */
    public static function receiptCases(): array
    {
        $expected = self::expected();
        $cases = [];

        foreach ($expected['receipts'] as $name => $case) {
            $cases[$name] = [[...$expected['default_options'], ...($case['options'] ?? $expected['receipt_options']), '--receipt', $case['receipt'], ...$case['bundles']], $case];
        }

        return $cases;
    }

    /**
     * @return array<string, array{0: list<string>, 1: array<string, mixed>}>
     */
    public static function reconcileCases(): array
    {
        $expected = self::expected();
        $cases = [];

        foreach ($expected['reconcile'] as $name => $case) {
            $arguments = [...$expected['default_options'], ...$expected['receipt_options'], '--reconcile', $case['registry'], $case['log']];

            if (isset($case['receipts'])) {
                $arguments = [...$arguments, '--receipts', $case['receipts']];
            }

            $cases[$name] = [$arguments, $case];
        }

        return $cases;
    }

    /**
     * @param  list<string>  $arguments
     * @param  array<string, mixed>  $case
     */
    #[DataProvider('receiptCases')]
    public function testEveryReceiptCaseGivesItsRecordedVerdict(array $arguments, array $case): void
    {
        $document = $this->verify($arguments);

        self::assertSame($case['exit'], $document['exit_code']);
        self::assertSame($case['result'], $document['result']);
        self::assertSame($case['results'], $document['results']);
        self::assertSame($case['reason'], $document['reason']);
        self::assertSame($case['subject'], $document['receipt']['subject'] ?? null);
    }

    /**
     * @param  list<string>  $arguments
     * @param  array<string, mixed>  $case
     */
    #[DataProvider('reconcileCases')]
    public function testEveryReconcileCaseGivesItsRecordedVerdict(array $arguments, array $case): void
    {
        $document = $this->verify($arguments);

        self::assertSame($case['exit'], $document['exit_code']);
        self::assertSame($case['result'], $document['result']);
        self::assertSame($case['results'], $document['results']);
        self::assertSame($case['reason'], $document['reason']);
        self::assertSame($case['decisions'], $document['counts']['decisions']);
        self::assertSame($case['receipts_checked'], $document['receipts_checked']);
    }

    public function testTheValidRegistryReportsItsOutcomesPerCredential(): void
    {
        $expected = self::expected();
        $document = $this->verify([...$expected['default_options'], ...$expected['receipt_options'], '--reconcile', 'corpus/registry/valid-registry.zip', 'corpus/registry/valid-log.zip']);

        self::assertSame(['accepted' => 2, 'replay' => 1, 'conflict' => 1, 'invalid' => 1, 'refused_early' => 1, 'refused_late' => 1], $document['counts']['outcomes']);
        self::assertSame(['refused_early' => 1, 'accepted' => 1], $document['counts']['credentials'][RegistryHistory::SECOND]);
    }

    public function testTheApiEnvelopeOfAReceiptIsReadThroughItsReceipt(): void
    {
        $expected = self::expected();
        $receipt = json_decode((string) file_get_contents(dirname(__DIR__).'/corpus/registry/receipts/04-accepted.json'), false);
        $path = sys_get_temp_dir().DIRECTORY_SEPARATOR.'sigilbase-envelope-'.bin2hex(random_bytes(4)).'.json';
        file_put_contents($path, json_encode(['id' => 'x', 'receipt' => $receipt, 'receipt_pending' => false]));

        try {
            $document = $this->verify([...$expected['default_options'], ...$expected['receipt_options'], '--receipt', $path]);
        } finally {
            unlink($path);
        }

        self::assertSame('pass', $document['result']);
    }

    public function testAReceiptSignedBeforeItWasReceivedIsMisshapen(): void
    {
        $expected = self::expected();
        $receipt = json_decode((string) file_get_contents(dirname(__DIR__).'/corpus/registry/receipts/04-accepted.json'), false);
        $receipt->body->signed_at = '2026-07-01T09:09:59.000000Z';
        $receipt->signature = RegistryHistory::sign($receipt->body);
        $path = sys_get_temp_dir().DIRECTORY_SEPARATOR.'sigilbase-early-'.bin2hex(random_bytes(4)).'.json';
        file_put_contents($path, json_encode($receipt));

        try {
            $document = $this->verify([...$expected['default_options'], ...$expected['receipt_options'], '--receipt', $path]);
        } finally {
            unlink($path);
        }

        self::assertSame('fail', $document['result']);
        self::assertSame('RECEIPT_SHAPE', $document['reason']);
    }

    public function testAReceiptKeyFileWithAForgedIdIsAnError(): void
    {
        $keys = RegistryHistory::receiptKeys();
        $keys['keys'][0]['key_id'] = str_repeat('ab', 32);
        $path = sys_get_temp_dir().DIRECTORY_SEPARATOR.'sigilbase-forged-'.bin2hex(random_bytes(4)).'.json';
        file_put_contents($path, json_encode($keys));

        try {
            $document = $this->verify(['--receipt-keys', $path, '--receipt', 'corpus/registry/receipts/04-accepted.json']);
        } finally {
            unlink($path);
        }

        self::assertSame(2, $document['exit_code']);
    }

    public function testOrdinaryVerificationOfARegistryBundleIsUnchanged(): void
    {
        $expected = self::expected();

        foreach (['valid-registry', 'valid-log'] as $bundle) {
            $document = $this->verify([...$expected['default_options'], 'corpus/registry/'.$bundle.'.zip']);

            self::assertSame('pass', $document['result']);
            self::assertArrayNotHasKey('reason', $document);
        }
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
