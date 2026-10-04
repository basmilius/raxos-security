<?php
declare(strict_types=1);

use Raxos\Error\InvalidArgumentException;
use Raxos\Security\Error\{UlidInvalidLengthException, UlidTimestampTooLargeException, UlidWrongCharactersException};
use Raxos\Security\Id\Ulid;

covers(Ulid::class);

it('round trips ULID timestamps including the 48-bit boundaries', function (int $timestamp): void {
    $id = Ulid::fromTimestamp($timestamp);
    expect(strlen((string)$id))->toBe(26)
        ->and($id->toTimestamp())->toBe($timestamp)
        ->and(Ulid::fromString(strtolower((string)$id))->toTimestamp())->toBe($timestamp)
        ->and((string)Ulid::fromString((string)$id, true))->toBe(strtolower((string)$id));
})->with([0, 1, 1_469_918_176_387, Ulid::TIME_MAX]);

it('generates strictly increasing ULIDs within one millisecond', function (): void {
    $ids = array_map(static fn(int $index): string => (string)Ulid::fromTimestamp(42_000), range(1, 100));
    $ordered = $ids;
    sort($ordered);
    expect($ids)->toBe($ordered)->and(array_unique($ids))->toHaveCount(100);
});

it('rejects out-of-range ULID timestamps', function (int $timestamp, string $exception): void {
    expect(fn(): Ulid => Ulid::fromTimestamp($timestamp))->toThrow($exception);
})->with([[-1, InvalidArgumentException::class], [Ulid::TIME_MAX + 1, UlidTimestampTooLargeException::class]]);

it('rejects malformed ULID strings', function (string $value, string $exception): void {
    expect(fn(): Ulid => Ulid::fromString($value))->toThrow($exception);
})->with([
    ['', UlidInvalidLengthException::class],
    [str_repeat('I', 26), UlidWrongCharactersException::class],
    [str_repeat('Z', 26), UlidTimestampTooLargeException::class],
]);

it('generates an identifier in the current timestamp interval', function (): void {
    $start = (int)(microtime(true) * 1000);
    $id = Ulid::generate(true);
    $end = (int)(microtime(true) * 1000);
    expect($id->toTimestamp())->toBeGreaterThanOrEqual($start)->toBeLessThanOrEqual($end)
        ->and((string)$id)->toBe(strtolower((string)$id));
});

it('rejects malformed timestamp characters in directly constructed identifiers', function (): void {
    expect(fn() => new Ulid('IIIIIIIIII', str_repeat('0', 16))->toTimestamp())->toThrow(UlidWrongCharactersException::class);
});
