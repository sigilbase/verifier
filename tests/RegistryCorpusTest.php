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

    public function testAKeyIdWithATrailingNewlineIsMisshapen(): void
    {
        $expected = self::expected();
        $receipt = json_decode((string) file_get_contents(dirname(__DIR__).'/corpus/registry/receipts/04-accepted.json'), false);
        $receipt->body->key_id .= "\n";
        $receipt->signature = RegistryHistory::sign($receipt->body);
        $path = sys_get_temp_dir().DIRECTORY_SEPARATOR.'sigilbase-newline-'.bin2hex(random_bytes(4)).'.json';
        file_put_contents($path, json_encode($receipt));

        try {
            $document = $this->verify([...$expected['default_options'], ...$expected['receipt_options'], '--receipt', $path]);
        } finally {
            unlink($path);
        }

        self::assertSame('RECEIPT_SHAPE', $document['reason']);
    }

    public function testAWindowWhoseKeyIsNotTextNamesNoKey(): void
    {
        $window = (object) ['key' => ['not', 'text'], 'open_at' => '2026-07-01T09:00:00.000000Z', 'close_at' => '2026-07-01T09:30:00.000000Z'];
        $rules = (object) ['v' => 1];
        $full = clone $rules;
        $full->windows = [$window];
        $hash = 'sha256:'.hash('sha256', canonical_encode($full));

        $record = static fn (int $seq, string $at, string $action, object $payload): object => (object) ['seq' => $seq, 'received_at' => $at, 'action' => $action, 'payload' => $payload];

        $log = [
            1 => $record(1, '2026-07-01T09:00:00.000000Z', 'policy.committed', (object) ['version' => 1, 'policy_hash' => $hash, 'effective_at' => '2026-07-01T09:00:00.000000Z', 'policy' => $rules, 'windows' => (object) ['count' => 1, 'parts' => 1]]),
            2 => $record(2, '2026-07-01T09:00:00.000000Z', 'policy.windows', (object) ['version' => 1, 'part' => 1, 'parts' => 1, 'windows' => [$window]]),
            3 => $record(3, '2026-07-01T11:00:00.000000Z', 'ingress.invalid', (object) ['outcome' => 'invalid', 'credential' => 'k']),
        ];

        $view = static fn (array $manifest, array $events): array => ['manifest' => json_decode((string) json_encode($manifest), false), 'events' => $events, 'checkpoints' => []];

        require_once dirname(__DIR__).'/verify.php';

        // The overdue window is reported as unclosed under the empty key,
        // and the run goes on: no TypeError from a key that is an array.
        // Required inside a method, verify.php's top-level state is local to
        // the require: the run's globals are set here instead.
        $GLOBALS['failures'] = [];
        $GLOBALS['notes'] = [];
        $GLOBALS['reason'] = null;
        $GLOBALS['quiet'] = true;
        $GLOBALS['results'] = ['content_integrity' => 'pass', 'signing_identity' => 'pass', 'timestamps' => 'pass', 'scope' => 'pass', 'redactions' => 'pass'];
        $GLOBALS['trustedReceiptKeys'] = [];
        $result = reconcile_registry(
            $view(['stream' => ['public_id' => 'r'], 'range' => ['from' => 1, 'to' => 0]], []),
            $view(['decision_log_for' => ['public_id' => 'r'], 'range' => ['from' => 1, 'to' => 3]], $log),
            [],
        );

        self::assertSame(1, $result['counts']['decisions']);
        self::assertStringContainsString('WINDOW_CLOSE: key []', implode("\n", $GLOBALS['failures']));
    }

    public function testATrustedAnchorAfterASealDeadlineTurnsAMissingRecordIntoAFailure(): void
    {
        require_once dirname(__DIR__).'/verify.php';

        $root = dirname(__DIR__).'/corpus/registry/';
        $receipt = $root.'receipts/13-refused_late.json';
        $sealBy = json_decode((string) file_get_contents($receipt), false)->body->seal_by;

        // The truncated log ends at 11:10 and its last checkpoint a minute
        // later; the dropped refusal was due sealed at 11:35. Without an
        // anchor the run cannot tell it from a later decision; with one a
        // timestamp authority dated after 11:35, it is missing.
        $run = function (?int $anchoredAt) use ($root, $receipt): array {
            $GLOBALS['failures'] = [];
            $GLOBALS['notes'] = [];
            $GLOBALS['reason'] = null;
            $GLOBALS['unconfirmedReason'] = null;
            $GLOBALS['quiet'] = true;
            $GLOBALS['results'] = ['content_integrity' => 'pass', 'signing_identity' => 'pass', 'timestamps' => 'pass', 'scope' => 'pass', 'redactions' => 'pass'];
            $GLOBALS['trustedReceiptKeys'] = load_receipt_key_file($root.'receipt-keys.json');

            reconcile_registry(
                load_verified_bundle($root.'truncated-tail-registry.zip') + ['anchored_at' => null],
                load_verified_bundle($root.'truncated-tail-log.zip') + ['anchored_at' => $anchoredAt],
                [$receipt],
            );

            return [run_reason(), $GLOBALS['results']['content_integrity'], $GLOBALS['results']['scope']];
        };

        $after = (new \DateTimeImmutable($sealBy))->getTimestamp() + 60;

        self::assertSame(['RECEIPT_NOT_LOGGED', 'pass', 'unconfirmed'], $run(null));
        self::assertSame(['RECEIPT_NOT_LOGGED', 'pass', 'unconfirmed'], $run($after - 120));
        self::assertSame(['RECEIPT_NOT_LOGGED', 'fail', 'pass'], $run($after));
    }

    public function testEveryReceiptFileInTheDirectoryIsCountedAndNothingElse(): void
    {
        $expected = self::expected();
        $dir = sys_get_temp_dir().DIRECTORY_SEPARATOR.'sigilbase-receipts-[x]-'.bin2hex(random_bytes(4));
        mkdir($dir);
        mkdir($dir.'/sub.json');
        copy(dirname(__DIR__).'/corpus/registry/receipts/04-accepted.json', $dir.'/a.json');
        copy(dirname(__DIR__).'/corpus/registry/receipts/04-accepted.json', $dir.'/.hidden.json');
        file_put_contents($dir.'/b.json', '{"not": "a receipt"}');
        file_put_contents($dir.'/c.txt', 'ignored');

        try {
            $document = $this->verify([...$expected['default_options'], ...$expected['receipt_options'], '--reconcile', 'corpus/registry/valid-registry.zip', 'corpus/registry/valid-log.zip', '--receipts', $dir]);
        } finally {
            foreach (['a.json', '.hidden.json', 'b.json', 'c.txt'] as $file) {
                unlink($dir.'/'.$file);
            }

            rmdir($dir.'/sub.json');
            rmdir($dir);
        }

        self::assertSame(2, $document['receipts_checked']);
        self::assertSame('RECEIPT_SHAPE', $document['reason']);
    }

    public function testAFailureOutranksAnUnconfirmedReceiptAsTheReason(): void
    {
        $expected = self::expected();
        $dir = sys_get_temp_dir().DIRECTORY_SEPARATOR.'sigilbase-mixed-'.bin2hex(random_bytes(4));
        mkdir($dir);

        // First in name order: a receipt signed by a key nobody trusts.
        $stranger = json_decode((string) file_get_contents(dirname(__DIR__).'/corpus/registry/receipts/04-accepted.json'), false);
        $secret = sodium_crypto_sign_secretkey(sodium_crypto_sign_keypair());
        $stranger->body->key_id = hash('sha256', sodium_crypto_sign_publickey_from_secretkey($secret));
        $stranger->signature = RegistryHistory::sign($stranger->body, $secret);
        file_put_contents($dir.'/00-stranger.json', json_encode($stranger));
        copy(dirname(__DIR__).'/corpus/registry/receipts-unlogged/14-refused_late.json', $dir.'/14-refused_late.json');

        try {
            $document = $this->verify([...$expected['default_options'], ...$expected['receipt_options'], '--reconcile', 'corpus/registry/valid-registry.zip', 'corpus/registry/valid-log.zip', '--receipts', $dir]);
        } finally {
            array_map('unlink', glob($dir.'/*.json') ?: []);
            rmdir($dir);
        }

        self::assertSame('fail', $document['result']);
        self::assertSame('RECEIPT_NOT_LOGGED', $document['reason']);
    }

    public function testAWindowWithoutACloseIsNotAWarning(): void
    {
        require_once dirname(__DIR__).'/verify.php';

        $window = (object) ['key' => 'k-q1', 'open_at' => '2026-07-01T09:00:00.000000Z'];
        $rules = (object) ['v' => 1, 'registry' => 'r'];
        $full = clone $rules;
        $full->windows = [$window];
        $hash = 'sha256:'.hash('sha256', canonical_encode($full));
        $record = static fn (int $seq, string $action, object $payload): object => (object) ['seq' => $seq, 'received_at' => '2026-07-01T11:00:00.000000Z', 'action' => $action, 'payload' => $payload];
        $view = static fn (array $manifest, array $events): array => ['manifest' => json_decode((string) json_encode($manifest), false), 'events' => $events, 'checkpoints' => []];

        $GLOBALS['failures'] = [];
        $GLOBALS['notes'] = [];
        $GLOBALS['reason'] = null;
        $GLOBALS['unconfirmedReason'] = null;
        $GLOBALS['quiet'] = true;
        $GLOBALS['results'] = ['content_integrity' => 'pass', 'signing_identity' => 'pass', 'timestamps' => 'pass', 'scope' => 'pass', 'redactions' => 'pass'];

        set_error_handler(static function (int $severity, string $message): never {
            throw new \ErrorException($message, 0, $severity);
        });

        try {
            reconcile_registry(
                $view(['stream' => ['public_id' => 'r'], 'range' => ['from' => 1, 'to' => 0]], []),
                $view(['decision_log_for' => ['public_id' => 'r'], 'range' => ['from' => 1, 'to' => 3]], [
                    1 => $record(1, 'policy.committed', (object) ['version' => 1, 'policy_hash' => $hash, 'effective_at' => '2026-07-01T09:00:00.000000Z', 'policy' => $rules, 'windows' => (object) ['count' => 1, 'parts' => 1]]),
                    2 => $record(2, 'policy.windows', (object) ['version' => 1, 'part' => 1, 'parts' => 1, 'windows' => [$window]]),
                    3 => $record(3, 'window.closed', (object) ['key' => 'k-q1', 'outcome' => 'missing', 'accepted' => null, 'close_at' => '2026-07-01T10:00:00.000000Z', 'policy_hash' => $hash]),
                ]),
                [],
            );
        } finally {
            restore_error_handler();
        }

        self::assertStringContainsString('WINDOW_CLOSE', implode("\n", $GLOBALS['failures']));
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
