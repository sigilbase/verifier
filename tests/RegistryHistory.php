<?php

declare(strict_types=1);

namespace Sigilbase\Verifier\Tests;

use DateTimeImmutable;

/**
 * A registry and its decision log telling one consistent story (FORMAT.md,
 * "Receipts and registries"), written as two bundles and the receipts its
 * submitters hold, under the published corpus test key and a corpus receipt
 * key. Shared by the tests and by tools/build-corpus-registry.php, so the
 * committed fixtures and the tests exercise one and the same history.
 *
 * The story, on 1 July 2026: a frozen policy with three windows; a key in
 * the snapshot accepted for acme-q3, then replayed, then conflicted; an
 * invalid body; a second key issued, refused early, the beta-q3 window
 * closing missing, the second key accepted for gamma-q3 and then revoked;
 * a late submission for beta-q3.
 *
 * Each variant breaks one reconcile rule while keeping both bundles
 * genuinely signed, the way an operator who rewrote its own history would
 * have to: only the registry rules can catch it. A few (registry-ahead,
 * paused) are honest histories the rules must let pass.
 */
final class RegistryHistory
{
    public const REGISTRY_STREAM = '019b7ca9-8c88-70c0-8000-0000000000d1';

    public const LOG_STREAM = '019b7ca9-8c88-70c0-8000-0000000000d2';

    public const REGISTRY_PUBLIC_ID = 'a1b2c3d4e5f60718293a4b5c6d7e8f90';

    public const TENANT_PUBLIC_ID = '0f1e2d3c4b5a69788796a5b4c3d2e1f0';

    /** The corpus receipt key's seed (published: it signs fixtures only). */
    public const RECEIPT_SEED = 'c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7';

    public const FILER = 'sgb_filer000000001';

    public const SECOND = 'sgb_second00000002';

    public const VARIANTS = ['valid', 'deleted-decision', 'extra-event', 'double-acceptance', 'missing-close', 'revoked-credential', 'late-seal', 'late-acceptance', 'frozen-amended', 'live-log', 'registry-ahead', 'phantom-acceptance', 'false-conflict', 'pending-amendment', 'negative-notice', 'paused', 'false-pause', 'backdated-tail', 'stale-log', 'truncated-tail', 'truncated-accept'];

    /**
     * The variant's own changes to the first policy's rules, while it is written.
     *
     * @var array<string, mixed>
     */
    private static array $rules = [];

    /**
     * The receipt key: [public key hex, secret key, key_id].
     *
     * @return array{0: string, 1: string, 2: string}
     */
    public static function receiptKey(): array
    {
        $keypair = sodium_crypto_sign_seed_keypair((string) hex2bin(self::RECEIPT_SEED));
        $public = sodium_crypto_sign_publickey($keypair);

        return [bin2hex($public), sodium_crypto_sign_secretkey($keypair), hash('sha256', $public)];
    }

    /**
     * The receipt key set, in the shape of /api/v1/receipt-keys.
     *
     * @return array{keys: list<array<string, string|null>>}
     */
    public static function receiptKeys(?string $retiredAt = null): array
    {
        [$public, , $keyId] = self::receiptKey();

        return ['keys' => [[
            'key_id' => $keyId,
            'public_key' => $public,
            'algorithm' => 'ed25519',
            'created_at' => '2026-06-01T00:00:00.000000Z',
            'retired_at' => $retiredAt,
        ]]];
    }

    /**
     * @param  array<string, mixed>|null  $overrides  changes to the rules; the variant's own when null
     * @return array{rules: object, windows: list<object>, hash: string}
     */
    public static function policy(?array $overrides = null): array
    {
        [, , $keyId] = self::receiptKey();

        $rules = (object) [
            'v' => 1,
            'registry' => self::REGISTRY_PUBLIC_ID,
            'commitment_key_pattern' => '[a-z]+-q[1-4]',
            'payload_schema' => (object) [
                'type' => 'object',
                'required' => ['filing_hash'],
                'properties' => (object) ['filing_hash' => (object) ['type' => 'string', 'maxLength' => 71]],
                'additionalProperties' => false,
            ],
            'throttle_record_cap' => 60,
            'msd_seconds' => 900,
            'receipt_key_id' => $keyId,
            'amendment' => 'frozen',
        ];

        foreach ($overrides ?? self::$rules as $field => $value) {
            $rules->{$field} = $value;
        }

        $windows = [
            (object) ['key' => 'acme-q3', 'open_at' => '2026-07-01T09:00:00.000000Z', 'close_at' => '2026-07-01T12:00:00.000000Z'],
            (object) ['key' => 'beta-q3', 'open_at' => '2026-07-01T09:00:00.000000Z', 'close_at' => '2026-07-01T10:30:00.000000Z'],
            (object) ['key' => 'gamma-q3', 'open_at' => '2026-07-01T11:00:00.000000Z', 'close_at' => '2026-07-01T12:00:00.000000Z'],
            (object) ['key' => 'delta-q3', 'open_at' => '2026-07-01T09:00:00.000000Z', 'close_at' => '2026-07-01T12:00:00.000000Z'],
        ];

        $full = clone $rules;
        $full->windows = $windows;

        return ['rules' => $rules, 'windows' => $windows, 'hash' => 'sha256:'.hash('sha256', canonical_encode($full))];
    }

    /**
     * Write the variant's registry and decision-log bundles into $dir
     * (registry/ and log/) and return the receipts the submitters hold,
     * file name => document.
     *
     * @return array<string, array{body: object, signature: string}>
     */
    public static function write(string $seed, string $dir, string $variant): array
    {
        self::$rules = match ($variant) {
            'pending-amendment' => ['amendment' => 'notice', 'notice_seconds' => 86400],
            'negative-notice' => ['amendment' => 'notice', 'notice_seconds' => -86400],
            default => [],
        };

        $registryGenerator = new FixtureGenerator($seed, self::REGISTRY_STREAM);
        $logGenerator = new FixtureGenerator($seed, self::LOG_STREAM);

        // ---- the registry: its accepted events ------------------------------

        $registrySpecs = [
            self::submission('acme-q3', '2026-07-01T09:10:00.000000Z', 'filer:acme', 'aa'),
            self::submission('gamma-q3', '2026-07-01T11:05:00.000000Z', 'filer:gamma', 'cc'),
        ];

        if ($variant === 'extra-event' || $variant === 'double-acceptance' || $variant === 'backdated-tail') {
            $registrySpecs[] = self::submission('acme-q3', '2026-07-01T11:15:00.000000Z', 'filer:acme', 'dd');
        }

        if ($variant === 'stale-log') {
            $registrySpecs[] = self::submission('beta-q3', '2026-07-01T11:20:00.000000Z', 'filer:beta', 'bb');
        }

        if ($variant === 'late-acceptance') {
            $registrySpecs[] = self::submission('beta-q3', '2026-07-01T11:25:00.000000Z', 'filer:beta', 'bb');
        }

        if ($variant === 'live-log' || $variant === 'registry-ahead') {
            $registrySpecs[] = self::submission('delta-q3', '2026-07-01T11:30:00.000000Z', 'filer:delta', 'ee');
        }

        // Every record sealed a minute after it was received, well inside
        // its seal_by, as a seal running every few minutes would.
        $registryOptions = [
            'stream' => ['slug' => 'filings', 'name' => 'Filings 2026', 'public_id' => self::REGISTRY_PUBLIC_ID],
            'per_checkpoint' => 1,
        ];

        if ($variant === 'late-seal') {
            // Sealed twenty minutes after its events: past every seal_by.
            $registryOptions['created_at'] = static fn (object $last): string => (new DateTimeImmutable($last->received_at))->modify('+20 minutes')->format('Y-m-d\TH:i:s.u\Z');
        }

        $registryEvents = $registryGenerator->writeStreamBundle($dir.DIRECTORY_SEPARATOR.'registry', array_map(
            static fn (array $spec): array => $spec['event'],
            $registrySpecs,
        ), $registryOptions);

        if ($variant === 'live-log') {
            // Exported before its third event arrived: the log, exported
            // after, accepts an event this bundle does not hold yet.
            $registryGenerator->writeStreamBundle($dir.DIRECTORY_SEPARATOR.'registry', array_map(
                static fn (array $spec): array => $spec['event'],
                array_slice($registrySpecs, 0, 2),
            ), $registryOptions);
        }

        // ---- the decision log ---------------------------------------------

        $policy = self::policy();
        $acme = $registryEvents[0];
        $gamma = $registryEvents[1];

        $decisions = [
            self::record('2026-07-01T09:00:00.000000Z', 'policy.committed', [
                'v' => 1, 'version' => 1, 'policy_hash' => $policy['hash'], 'effective_at' => '2026-07-01T09:00:00.000000Z',
                'policy' => $policy['rules'], 'windows' => (object) ['count' => 4, 'parts' => 1],
            ], 'user:owner-1'),
            self::record('2026-07-01T09:00:00.000000Z', 'policy.windows', [
                'v' => 1, 'version' => 1, 'part' => 1, 'parts' => 1, 'windows' => $policy['windows'],
            ], 'user:owner-1'),
            self::record('2026-07-01T09:00:00.000000Z', 'credentials.snapshot', [
                'v' => 1, 'part' => 1, 'parts' => 1, 'credentials' => [(object) ['credential' => self::FILER, 'scope' => 'registry', 'expires_at' => null]],
            ], 'user:owner-1'),
            self::decision('accepted', '2026-07-01T09:10:00.000000Z', 'acme-q3', $registrySpecs[0]['digest'], self::FILER, $acme, $registrySpecs[0]['digest']),
            self::decision('replay', '2026-07-01T09:11:00.000000Z', 'acme-q3', $registrySpecs[0]['digest'], self::FILER, $acme, $registrySpecs[0]['digest']),
            self::decision('conflict', '2026-07-01T09:12:00.000000Z', 'acme-q3', self::otherDigest('acme-q3'), self::FILER, $acme, $registrySpecs[0]['digest'], ['digest_mismatch']),
            self::decision('invalid', '2026-07-01T09:13:00.000000Z', null, 'sha256:'.hash('sha256', '{"commitment_key": "acme-q3", oops'), self::FILER, null, null, ['body_not_object'], 'raw'),
            self::record('2026-07-01T09:20:00.000000Z', 'credential.issued', [
                'v' => 1, 'credential' => self::SECOND, 'scope' => 'all', 'expires_at' => null,
            ], 'user:owner-1'),
            self::decision('refused_early', '2026-07-01T09:30:00.000000Z', 'gamma-q3', self::otherDigest('gamma-early'), self::SECOND, null, null),
            self::record('2026-07-01T10:30:05.000000Z', 'window.closed', [
                'v' => 1, 'key' => 'beta-q3', 'outcome' => 'missing', 'accepted' => null,
                'close_at' => '2026-07-01T10:30:00.000000Z', 'policy_hash' => $policy['hash'],
            ], 'sigilbase:registry'),
            self::decision('accepted', '2026-07-01T11:05:00.000000Z', 'gamma-q3', $registrySpecs[1]['digest'], self::SECOND, $gamma, $registrySpecs[1]['digest']),
            self::record('2026-07-01T11:10:00.000000Z', 'credential.revoked', [
                'v' => 1, 'credential' => self::SECOND, 'scope' => 'all', 'expires_at' => null,
            ], 'user:owner-1'),
            self::decision('refused_late', '2026-07-01T11:20:00.000000Z', 'beta-q3', self::otherDigest('beta-late'), self::FILER, null, null),
        ];

        match ($variant) {
            // An operator drops the acceptance of acme-q3 and re-signs its log.
            'deleted-decision' => array_splice($decisions, 3, 1),
            // An event in the registry no decision accepts.
            'extra-event' => null,
            // acme-q3 accepted a second time, for the registry's third event.
            'double-acceptance' => array_splice($decisions, 12, 0, [
                self::decision('accepted', '2026-07-01T11:15:00.000000Z', 'acme-q3', $registrySpecs[2]['digest'], self::FILER, $registryEvents[2], $registrySpecs[2]['digest']),
            ]),
            // beta-q3 closed at 10:30 and the log never says so.
            'missing-close' => array_splice($decisions, 9, 1),
            // gamma-q3 accepted from the second key after its revocation.
            'revoked-credential' => self::moveRevocationBeforeGamma($decisions),
            // beta-q3 accepted at 11:25, after its window closed at 10:30.
            'late-acceptance' => array_push($decisions,
                self::decision('accepted', '2026-07-01T11:25:00.000000Z', 'beta-q3', $registrySpecs[2]['digest'], self::FILER, $registryEvents[2], $registrySpecs[2]['digest']),
            ),
            // The frozen policy amended, backdated to drop beta-q3's window.
            'frozen-amended' => array_push($decisions, ...self::backdatedAmendment()),
            // delta-q3 accepted after the registry bundle was exported.
            'live-log' => array_push($decisions,
                self::decision('accepted', '2026-07-01T11:30:00.000000Z', 'delta-q3', $registrySpecs[2]['digest'], self::FILER, $registryEvents[2], $registrySpecs[2]['digest']),
            ),
            // delta-q3 accepted at 11:30, after the log was exported: the
            // registry bundle, exported after it, holds the event.
            'registry-ahead' => null,
            // delta-q3 accepted at 09:40 as a third registry event, which the
            // registry, holding events to 11:05, never had.
            'phantom-acceptance' => array_splice($decisions, 9, 0, [
                self::decision('accepted', '2026-07-01T09:40:00.000000Z', 'delta-q3', self::otherDigest('delta-phantom'), self::FILER, (object) ['seq' => 3, 'entry_hash' => str_repeat('ab', 32)], self::otherDigest('delta-phantom')),
            ]),
            // delta-q3's first filing refused as a conflict with a holder
            // that was never accepted.
            'false-conflict' => array_splice($decisions, 9, 0, [
                self::decision('conflict', '2026-07-01T09:40:00.000000Z', 'delta-q3', self::otherDigest('delta-first'), self::FILER, (object) ['seq' => 99, 'entry_hash' => str_repeat('cd', 32)], self::otherDigest('delta-holder'), ['digest_mismatch']),
            ]),
            // Version 2, under the full day's notice, asks only an hour of its
            // own; version 3 amends it while it is still pending.
            'pending-amendment' => array_splice($decisions, 9, 0, [
                ...self::amendment(2, ['notice_seconds' => 3600], '2026-07-01T09:40:00.000000Z', '2026-07-02T09:40:00.000000Z'),
                ...self::amendment(3, ['notice_seconds' => 3600], '2026-07-01T09:45:00.000000Z', '2026-07-02T10:45:00.000000Z'),
            ]),
            // A notice period of minus a day: an amendment could take effect
            // a day before it was made.
            'negative-notice' => null,
            // Paused, a refusal while paused, resumed.
            'paused' => array_push($decisions,
                self::record('2026-07-01T11:21:00.000000Z', 'stream.paused', ['v' => 1], 'user:owner-1'),
                self::decision('refused_paused', '2026-07-01T11:22:00.000000Z', 'delta-q3', self::otherDigest('delta-paused'), self::FILER, null, null),
                self::record('2026-07-01T11:23:00.000000Z', 'stream.resumed', ['v' => 1], 'user:owner-1'),
            ),
            // An event no decision accepts, hidden behind a last log record
            // backdated to 08:00, so the event seems to come after the log.
            'backdated-tail' => array_push($decisions,
                self::record('2026-07-01T08:00:00.000000Z', 'credential.issued', [
                    'v' => 1, 'credential' => 'sgb_backdated00003', 'scope' => 'all', 'expires_at' => null,
                ], 'user:owner-1'),
            ),
            // A log exported at 09:10, before the registry took gamma-q3 and
            // a beta-q3 acceptance after its window closed: whether those
            // were decided at all cannot be told until the log is exported
            // again.
            'stale-log' => array_splice($decisions, 4),
            // The last decision, a receipted refusal, dropped from the log.
            'truncated-tail' => array_pop($decisions),
            // gamma-q3's acceptance and all after it dropped, the log then
            // sealed at 11:30, past the acceptance's 11:20 deadline.
            'truncated-accept' => array_splice($decisions, 10),
            // A refusal for a pause the log never records.
            'false-pause' => array_push($decisions,
                self::decision('refused_paused', '2026-07-01T11:22:00.000000Z', 'delta-q3', self::otherDigest('delta-paused'), self::FILER, null, null),
            ),
            default => null,
        };

        $logOptions = [
            'stream' => ['slug' => 'sigilbase-decisions-'.self::REGISTRY_PUBLIC_ID, 'name' => 'Decision log: Filings 2026', 'public_id' => 'e0e1e2e3e4e5e6e7e8e9eaebecedeeef'],
            'manifest' => ['decision_log_for' => ['id' => self::REGISTRY_STREAM, 'public_id' => self::REGISTRY_PUBLIC_ID, 'slug' => 'filings']],
            'per_checkpoint' => 1,
        ];

        if ($variant === 'truncated-accept') {
            // Each record sealed a minute after it, as usual, but the last
            // checkpoint signed at 11:30: the log known complete then.
            $lastSeq = count($decisions);
            $logOptions['created_at'] = static fn (object $last): string => $last->seq === $lastSeq
                ? '2026-07-01T11:30:00.000000Z'
                : (new DateTimeImmutable($last->received_at))->modify('+1 minute')->format('Y-m-d\TH:i:s.u\Z');
        }

        $logEvents = $logGenerator->writeStreamBundle($dir.DIRECTORY_SEPARATOR.'log', array_map(
            static fn (array $decision): array => $decision['event'],
            $decisions,
        ), $logOptions);

        // ---- the receipts the submitters hold -----------------------------

        $receipts = [];

        foreach ($logEvents as $event) {
            if (! str_starts_with($event->action, 'ingress.')) {
                continue;
            }

            $name = sprintf('%02d-%s.json', $event->seq, substr($event->action, strlen('ingress.')));
            $receipts[$name] = self::receipt($event, $policy['hash']);
        }

        self::$rules = [];

        return $receipts;
    }

    /**
     * A receipt signed with the corpus receipt key, as the application signs
     * one for the decision record given.
     *
     * @return array{body: object, signature: string}
     */
    public static function receipt(object $record, string $policyHash, ?string $signedAt = null): array
    {
        [, $secret, $keyId] = self::receiptKey();
        $payload = $record->payload;

        $body = (object) [
            'v' => 'sigilbase-receipt/1',
            'tenant' => self::TENANT_PUBLIC_ID,
            'stream' => self::REGISTRY_PUBLIC_ID,
            'decision_seq' => $record->seq,
            'outcome' => $payload->outcome,
            'commitment_key' => $payload->commitment_key,
            'policy_hash' => $policyHash,
            'request_digest' => $payload->request_digest,
            'digest_kind' => $payload->digest_kind,
            'credential' => $payload->credential,
            'accepted' => $payload->accepted,
            'received_at' => $record->received_at,
            'seal_by' => (new DateTimeImmutable($record->received_at))->modify('+900 seconds')->format('Y-m-d\TH:i:s.u\Z'),
        ];

        if ($payload->reasons !== []) {
            $body->reasons = $payload->reasons;
        }

        $body->key_id = $keyId;
        $body->signed_at = $signedAt ?? (new DateTimeImmutable($record->received_at))->modify('+250 milliseconds')->format('Y-m-d\TH:i:s.u\Z');

        return ['body' => $body, 'signature' => self::sign($body, $secret)];
    }

    public static function sign(object $body, ?string $secret = null): string
    {
        $secret ??= self::receiptKey()[1];

        return base64_encode(sodium_crypto_sign_detached('sigilbase-receipt/1'."\n".canonical_encode($body), $secret));
    }

    /**
     * @return array{event: array<string, mixed>, digest: string}
     */
    private static function submission(string $key, string $receivedAt, string $actor, string $salt): array
    {
        $event = [
            'occurred_at' => (new DateTimeImmutable($receivedAt))->modify('-1 minute')->format('Y-m-d\TH:i:s.u\Z'),
            'received_at' => $receivedAt,
            'actor' => $actor,
            'action' => 'filing.submitted',
            'resource' => null,
            'payload' => (object) ['filing_hash' => 'sha256:'.str_repeat($salt, 32)],
        ];

        $line = (object) [...$event, 'payload_hash' => hash('sha256', canonical_encode($event['payload']))];

        return ['event' => $event, 'digest' => request_digest($line, $key)];
    }

    private static function otherDigest(string $salt): string
    {
        return 'sha256:'.hash('sha256', 'another submission: '.$salt);
    }

    /**
     * @param  array<string, mixed>  $payload
     * @return array{event: array<string, mixed>}
     */
    private static function record(string $at, string $action, array $payload, string $actor): array
    {
        return ['event' => [
            'occurred_at' => $at,
            'received_at' => $at,
            'actor' => $actor,
            'action' => $action,
            'resource' => self::REGISTRY_PUBLIC_ID,
            'payload' => (object) $payload,
        ]];
    }

    /**
     * @param  list<string>  $reasons
     * @return array{event: array<string, mixed>}
     */
    private static function decision(string $outcome, string $at, ?string $key, string $digest, string $credential, ?object $holder, ?string $heldDigest, array $reasons = [], string $kind = 'canonical'): array
    {
        return self::record($at, 'ingress.'.$outcome, [
            'v' => 1,
            'outcome' => $outcome,
            'commitment_key' => $key,
            'request_digest' => $digest,
            'digest_kind' => $kind,
            'credential' => $credential,
            'accepted' => $holder === null ? null : (object) ['sequence' => $holder->seq, 'entry_hash' => $holder->entry_hash, 'request_digest' => $heldDigest],
            'reasons' => $reasons,
            'received_at' => $at,
            'policy_hash' => self::policy()['hash'],
        ], 'sigilbase:ingress');
    }

    /**
     * A later policy version, recorded at $at and effective from
     * $effectiveAt: the first policy's windows under changed rules.
     *
     * @param  array<string, mixed>  $changes
     * @return list<array{event: array<string, mixed>}>
     */
    private static function amendment(int $version, array $changes, string $at, string $effectiveAt): array
    {
        $policy = self::policy([...self::$rules, ...$changes]);

        return [
            self::record($at, 'policy.amended', [
                'v' => 1, 'version' => $version, 'policy_hash' => $policy['hash'], 'effective_at' => $effectiveAt,
                'policy' => $policy['rules'], 'windows' => (object) ['count' => count($policy['windows']), 'parts' => 1],
            ], 'user:owner-1'),
            self::record($at, 'policy.windows', [
                'v' => 1, 'version' => $version, 'part' => 1, 'parts' => 1, 'windows' => $policy['windows'],
            ], 'user:owner-1'),
        ];
    }

    /**
     * A second policy amending the frozen first one, recorded at 11:30 and
     * effective from 09:00, without beta-q3's window.
     *
     * @return list<array{event: array<string, mixed>}>
     */
    private static function backdatedAmendment(): array
    {
        $policy = self::policy();
        $windows = array_values(array_filter($policy['windows'], static fn (object $window): bool => $window->key !== 'beta-q3'));
        $full = clone $policy['rules'];
        $full->windows = $windows;
        $hash = 'sha256:'.hash('sha256', canonical_encode($full));

        return [
            self::record('2026-07-01T11:30:00.000000Z', 'policy.amended', [
                'v' => 1, 'version' => 2, 'policy_hash' => $hash, 'effective_at' => '2026-07-01T09:00:00.000000Z',
                'policy' => $policy['rules'], 'windows' => (object) ['count' => count($windows), 'parts' => 1],
            ], 'user:owner-1'),
            self::record('2026-07-01T11:30:00.000000Z', 'policy.windows', [
                'v' => 1, 'version' => 2, 'part' => 1, 'parts' => 1, 'windows' => $windows,
            ], 'user:owner-1'),
        ];
    }

    /**
     * @param  list<array{event: array<string, mixed>}>  $decisions
     */
    private static function moveRevocationBeforeGamma(array &$decisions): void
    {
        [$revocation] = array_splice($decisions, 11, 1);
        $revocation['event']['occurred_at'] = '2026-07-01T11:00:00.000000Z';
        $revocation['event']['received_at'] = '2026-07-01T11:00:00.000000Z';
        array_splice($decisions, 10, 0, [$revocation]);
    }
}
