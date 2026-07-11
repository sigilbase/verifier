<?php

declare(strict_types=1);

namespace Sigilbase\Verifier\Tests;

use RuntimeException;
use ZipArchive;

/**
 * Generates evidence bundles from scratch — its own Ed25519 keypair, its
 * own hash chain, its own Merkle trees — using the verifier's canonical
 * JSON and Merkle functions (verify.php is require()d as a library; its
 * CLI does not run when required). The bundles are structurally identical
 * to real Sigilbase exports at format 1.1 minus the optional anchor and
 * consistency files, which the format marks optional.
 *
 * Payloads deliberately include non-ASCII keys and astral-plane characters
 * so canonical key ordering (UTF-16 code units, no mbstring) is exercised
 * end to end.
 */
final class FixtureGenerator
{
    // No type on the constant: typed class constants are PHP 8.3+ and this
    // repository supports 8.2.
    private const ZERO_HASH = '0000000000000000000000000000000000000000000000000000000000000000';

    public readonly string $streamId;

    public readonly string $publicKeyHex;

    private readonly string $secretKey;

    public function __construct()
    {
        require_once __DIR__.'/../verify.php';

        $keypair = sodium_crypto_sign_keypair();

        $this->secretKey = sodium_crypto_sign_secretkey($keypair);
        $this->publicKeyHex = bin2hex(sodium_crypto_sign_publickey($keypair));

        // Random per instance: two generators are two different streams,
        // exactly like two different Sigilbase customers.
        $hex = bin2hex(random_bytes(16));
        $this->streamId = sprintf(
            '%s-%s-%s-%s-%s',
            substr($hex, 0, 8),
            substr($hex, 8, 4),
            substr($hex, 12, 4),
            substr($hex, 16, 4),
            substr($hex, 20, 12),
        );
    }

    /**
     * Write a valid bundle of $eventCount events sealed into checkpoints of
     * $perCheckpoint into $dir. $payloadSalt varies the event CONTENT while
     * keeping the stream identity: two bundles from the same generator with
     * different salts are the same stream telling two different histories —
     * the thing consistency proofs exist to catch.
     */
    public function writeBundle(string $dir, int $eventCount = 4, int $perCheckpoint = 2, string $payloadSalt = ''): string
    {
        if (! is_dir($dir) && ! mkdir($dir, 0755, true)) {
            throw new RuntimeException("could not create [{$dir}]");
        }

        $events = [];
        $prevHash = self::ZERO_HASH;

        foreach (range(1, $eventCount) as $sequence) {
            $payload = (object) [
                'n' => $sequence,
                'rôle' => 'admin'.$payloadSalt,
                'note' => "käse 𝄞 clef #{$sequence}",
            ];

            $payloadHash = hash('sha256', canonical_encode($payload));

            $occurredAt = sprintf('2026-07-01T09:%02d:00.000000Z', $sequence);
            $receivedAt = sprintf('2026-07-01T09:%02d:01.500000Z', $sequence);

            $entryHash = hash('sha256', canonical_encode((object) [
                'v' => 1,
                'stream' => $this->streamId,
                'seq' => $sequence,
                'occurred_at' => $occurredAt,
                'received_at' => $receivedAt,
                'actor' => "user:{$sequence}",
                'action' => 'role.granted',
                'resource' => "user:9f{$sequence}",
                'payload_hash' => $payloadHash,
                'prev' => $prevHash,
            ]));

            $events[] = (object) [
                'v' => 1,
                'seq' => $sequence,
                'occurred_at' => $occurredAt,
                'received_at' => $receivedAt,
                'actor' => "user:{$sequence}",
                'action' => 'role.granted',
                'resource' => "user:9f{$sequence}",
                'payload' => $payload,
                'payload_hash' => $payloadHash,
                'prev_hash' => $prevHash,
                'entry_hash' => $entryHash,
            ];

            $prevHash = $entryHash;
        }

        $checkpoints = [];
        $prevCheckpointHash = self::ZERO_HASH;

        foreach (array_chunk($events, $perCheckpoint) as $chunk) {
            $from = $chunk[0]->seq;
            $to = $chunk[count($chunk) - 1]->seq;

            $root = bin2hex(merkle_root(array_map(
                static fn (object $event): string => (string) hex2bin($event->entry_hash),
                $chunk,
            )));

            $createdAt = sprintf('2026-07-01T09:%02d:30.000000Z', $to);

            $checkpointHash = hash('sha256', canonical_encode((object) [
                'v' => 1,
                'stream' => $this->streamId,
                'from' => $from,
                'to' => $to,
                'root' => $root,
                'prev_checkpoint' => $prevCheckpointHash,
                'created_at' => $createdAt,
            ]));

            $checkpoints[] = (object) [
                'v' => 1,
                'stream' => $this->streamId,
                'from' => $from,
                'to' => $to,
                'root' => $root,
                'prev_checkpoint' => $prevCheckpointHash,
                'created_at' => $createdAt,
                'checkpoint_hash' => $checkpointHash,
                'signature' => bin2hex(sodium_crypto_sign_detached((string) hex2bin($checkpointHash), $this->secretKey)),
                'public_key' => $this->publicKeyHex,
            ];

            $prevCheckpointHash = $checkpointHash;
        }

        $manifest = [
            'format' => 'sigilbase-evidence/1.1',
            'generated_at' => '2026-07-01T10:00:00.000000Z',
            'stream' => ['id' => $this->streamId, 'slug' => 'fixture-stream', 'name' => 'Fixture stream'],
            'range' => ['from' => 1, 'to' => $eventCount],
            'event_count' => $eventCount,
            'signing_keys' => [
                ['public_key' => $this->publicKeyHex, 'created_at' => '2026-01-01T00:00:00.000000Z', 'retired_at' => null],
            ],
        ];

        file_put_contents(
            $dir.DIRECTORY_SEPARATOR.'manifest.json',
            json_encode($manifest, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR),
        );

        file_put_contents(
            $dir.DIRECTORY_SEPARATOR.'events.ndjson',
            implode("\n", array_map(canonical_encode(...), $events))."\n",
        );

        file_put_contents(
            $dir.DIRECTORY_SEPARATOR.'checkpoints.json',
            json_encode(['checkpoints' => $checkpoints], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR),
        );

        return $dir;
    }

    /**
     * Zip an extracted bundle directory (requires ext-zip; tests that need
     * this skip when it is absent).
     */
    public function zip(string $dir, string $zipPath): string
    {
        $zip = new ZipArchive;

        if ($zip->open($zipPath, ZipArchive::CREATE | ZipArchive::OVERWRITE) !== true) {
            throw new RuntimeException("could not create [{$zipPath}]");
        }

        foreach (['manifest.json', 'events.ndjson', 'checkpoints.json'] as $file) {
            $zip->addFile($dir.DIRECTORY_SEPARATOR.$file, $file);
        }

        $zip->close();

        return $zipPath;
    }
}
