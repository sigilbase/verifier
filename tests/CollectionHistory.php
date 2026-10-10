<?php

declare(strict_types=1);

namespace Sigilbase\Verifier\Tests;

use Closure;
use RuntimeException;

/**
 * A connection's receipt stream telling a consistent story, as event
 * specs for FixtureGenerator::writeCollectionBundle: configuration, two
 * receipts, a declared gap, a settled day and a gapped day, a third
 * receipt, and a supplement to the first day. Shared by the tests and by
 * tools/build-corpus-collection.php, so the committed corpus fixtures and
 * the tests exercise one and the same history.
 */
final class CollectionHistory
{
    public const ZERO = '0000000000000000000000000000000000000000000000000000000000000000';

    public const RESOURCE = 'connection-stream:records';

    /**
     * @return list<array{action: string, resource: string|null, payload: object|Closure}>
     */
    public static function history(): array
    {
        return [
            ['action' => 'stream.config', 'resource' => self::RESOURCE, 'payload' => (object) [
                'config_version' => 1,
                'records_stream' => 'payments-feed',
                'stream_key' => 'records',
            ]],
            ['action' => 'collection.receipt', 'resource' => self::RESOURCE, 'payload' => self::receipt(1, null, [1, 3], 3)],
            ['action' => 'collection.receipt', 'resource' => self::RESOURCE, 'payload' => self::receipt(2, 3, [4, 5], 5)],
            ['action' => 'stream.gap', 'resource' => self::RESOURCE, 'payload' => static fn (array $built): object => (object) [
                'gap_version' => 1,
                'gap_id' => 'gap-1',
                'stream_key' => 'records',
                'from' => '2026-07-02T09:00:00.000000Z',
                'to' => '2026-07-02T10:00:00.000000Z',
                'reason' => 'connection_paused',
                'detected_at' => '2026-07-02T10:00:00.000000Z',
                'healable_until' => null,
                'declared_after_receipt_hash' => self::lastReceiptHash($built),
            ]],
            ['action' => 'stream.settled', 'resource' => self::RESOURCE, 'payload' => static fn (array $built): object => self::settled($built, '2026-07-01', 'settled', [], 0, null)],
            ['action' => 'stream.settled', 'resource' => self::RESOURCE, 'payload' => static fn (array $built): object => self::settled($built, '2026-07-02', 'gapped', [
                ['gap_id' => 'gap-1', 'from' => '2026-07-02T09:00:00.000000Z', 'to' => '2026-07-02T10:00:00.000000Z', 'reason' => 'connection_paused', 'healed' => false],
            ], 0, null)],
            ['action' => 'collection.receipt', 'resource' => self::RESOURCE, 'payload' => self::receipt(3, 5, [6, 6], 6)],
            ['action' => 'stream.settled', 'resource' => self::RESOURCE, 'payload' => static fn (array $built): object => self::settled($built, '2026-07-01', 'settled', [], 1, self::settlementOf($built, '2026-07-01'))],
        ];
    }

    /**
     * The history continued by a backfill that heals gap-1 (FORMAT.md,
     * "Collection records", rules 3 and 4): the backfill receipt, flagged
     * and carrying the interval it covers; the heal, naming the gap's
     * declaration and that receipt; and the supplement that settles the day
     * the gap had kept gapped, listing the gap as healed.
     *
     * @return list<array{action: string, resource: string, payload: object|Closure}>
     */
    public static function healed(): array
    {
        $covers = (object) ['from' => '2026-07-02T09:00:00.000000Z', 'to' => '2026-07-02T10:00:00.000000Z'];

        return [
            ...self::history(),
            ['action' => 'collection.receipt', 'resource' => self::RESOURCE, 'payload' => self::with(self::receipt(4, 6, [7, 7], 7), [
                'backfill' => true,
                'covers' => $covers,
            ])],
            ['action' => 'stream.gap_healed', 'resource' => self::RESOURCE, 'payload' => static fn (array $built): object => (object) [
                'heal_version' => 1,
                'gap_id' => 'gap-1',
                'stream_key' => 'records',
                'from' => '2026-07-02T09:00:00.000000Z',
                'to' => '2026-07-02T10:00:00.000000Z',
                'reason' => 'connection_paused',
                'declared' => (object) self::eventOf($built, 'stream.gap'),
                'backfill_receipt' => (object) self::eventOf($built, 'collection.receipt'),
                'covers' => $covers,
                'records_received' => 1,
                'healed_at' => '2026-07-04T03:00:00.000000Z',
            ]],
            ['action' => 'stream.settled', 'resource' => self::RESOURCE, 'payload' => static fn (array $built): object => self::settled($built, '2026-07-02', 'settled', [
                ['gap_id' => 'gap-1', 'from' => '2026-07-02T09:00:00.000000Z', 'to' => '2026-07-02T10:00:00.000000Z', 'reason' => 'connection_paused', 'healed' => true],
            ], 1, self::settlementOf($built, '2026-07-02'))],
        ];
    }

    /**
     * The latest event of an action so far, by sequence and entry hash.
     *
     * @param  list<object>  $built
     * @return array{sequence: int, entry_hash: string}
     */
    public static function eventOf(array $built, string $action): array
    {
        foreach (array_reverse($built) as $event) {
            if ($event->action === $action) {
                return ['sequence' => $event->seq, 'entry_hash' => $event->entry_hash];
            }
        }

        throw new RuntimeException("no {$action} yet");
    }

    /**
     * @param  array{0: int, 1: int}  $records
     */
    public static function receipt(int $index, ?int $cursorBefore, array $records, int $cursorAfter): Closure
    {
        return static fn (array $built): object => (object) [
            'receipt_version' => 1,
            'receipt_index' => $index,
            'prev_receipt_hash' => $index === 1 ? self::ZERO : self::lastReceiptHash($built),
            'connector' => 'generic-ndjson',
            'stream_key' => 'records',
            'records_stream' => 'payments-feed',
            'method' => 'push',
            'collected_by' => 'tenant',
            'page_hash' => hash('sha256', 'page-'.$index),
            'record_count' => $records[1] - $records[0] + 1,
            'records' => (object) ['from_sequence' => $records[0], 'to_sequence' => $records[1]],
            'duplicates_seen' => 0,
            'cursor_before' => $cursorBefore === null ? null : (object) ['sequence' => $cursorBefore],
            'cursor_after' => (object) ['sequence' => $cursorAfter],
        ];
    }

    /**
     * @param  list<object>  $built
     * @param  list<array<string, mixed>>  $gaps
     * @param  array{sequence: int, entry_hash: string}|null  $previous
     */
    public static function settled(array $built, string $day, string $state, array $gaps, int $supplement, ?array $previous): object
    {
        return (object) [
            'settlement_version' => 1,
            'stream_key' => 'records',
            'day' => $day,
            'state' => $state,
            'supplement' => $supplement,
            'previous_settlement' => $previous === null ? null : (object) $previous,
            'receipts' => (object) ['count' => self::receiptCount($built), 'last_receipt_hash' => self::lastReceiptHash($built)],
            'gaps' => $gaps,
        ];
    }

    /**
     * @param  list<object>  $built
     */
    public static function lastReceiptHash(array $built): ?string
    {
        foreach (array_reverse($built) as $event) {
            if ($event->action === 'collection.receipt') {
                return $event->entry_hash;
            }
        }

        return null;
    }

    /**
     * @param  list<object>  $built
     */
    public static function receiptCount(array $built): int
    {
        return count(array_filter($built, static fn (object $event): bool => $event->action === 'collection.receipt'));
    }

    /**
     * @param  list<object>  $built
     * @return array{sequence: int, entry_hash: string}
     */
    public static function settlementOf(array $built, string $day): array
    {
        foreach (array_reverse($built) as $event) {
            if ($event->action === 'stream.settled' && $event->payload->day === $day) {
                return ['sequence' => $event->seq, 'entry_hash' => $event->entry_hash];
            }
        }

        throw new RuntimeException("no settlement of {$day} yet");
    }

    /**
     * A payload (or payload closure) with some fields replaced.
     *
     * @param  array<string, mixed>  $changes
     */
    public static function with(object $payload, array $changes): Closure
    {
        return static function (array $built) use ($payload, $changes): object {
            $resolved = $payload instanceof Closure ? $payload($built) : $payload;

            return (object) [...(array) $resolved, ...$changes];
        };
    }

    /**
     * @return array<string, mixed>
     */
    public static function connectionJson(string $recordsStream = 'payments-feed'): array
    {
        return [
            'role' => 'receipts',
            'connection' => ['reference' => 'abc123def456', 'connector' => 'generic-ndjson'],
            'record_streams' => [['stream_key' => 'records', 'stream' => $recordsStream]],
        ];
    }
}
