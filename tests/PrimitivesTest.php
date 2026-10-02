<?php
declare(strict_types=1);

use Raxos\Security\Base64;
use Raxos\Security\Hmac;
use Raxos\Security\Id\NanoId;
use Raxos\Security\Id\Ulid;
use Raxos\Security\TokenGenerator;

it('preserves binary and falsey input in every Base64 variant', function (string $value): void {
    expect(Base64::decode(Base64::encode($value)))->toBe($value)
        ->and(Base64::decodeUrlSafe(Base64::encodeUrlSafe($value)))->toBe($value)
        ->and(Base64::decodeShuffle(Base64::encodeShuffle($value, 3), 3))->toBe($value);
})->with(['', '0', "\0\xff\xfe\0", 'Hello world!', 'é😀', str_repeat('raxos', 100)]);

it('rejects malformed Base64', function (string $value): void {
    expect(fn(): string => Base64::decode($value))->toThrow(InvalidArgumentException::class);
})->with(['%%%', 'a', 'YWJj!']);

it('matches the RFC4231 HMAC SHA256 vector and detects tampering', function (): void {
    // RFC 4231 section 4.2, test case 1.
    $expected = Base64::encodeUrlSafe(hex2bin('b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7'));
    $key = str_repeat("\x0b", 20);
    expect(Hmac::get('Hi There', $key))->toBe($expected)
        ->and(Hmac::matches($expected, 'Hi There', $key))->toBeTrue()
        ->and(Hmac::matches($expected, 'changed', $key))->toBeFalse()
        ->and(Hmac::matches($expected, 'Hi There', 'other'))->toBeFalse();
});

it('generates Nano IDs with the requested length and alphabet', function (int $length): void {
    $id = NanoId::generate($length);
    expect(strlen($id))->toBe($length)->and($id)->toMatch('/^[_\-0-9a-zA-Z]+$/');
})->with([1, 16, 21, 64]);

it('rejects non-positive Nano ID lengths', function (int $length): void {
    expect(fn(): string => NanoId::generate($length))->toThrow(Raxos\Error\InvalidArgumentException::class);
})->with([0, -1]);

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
})->with([[-1, Raxos\Error\InvalidArgumentException::class], [Ulid::TIME_MAX + 1, Raxos\Security\Error\UlidTimestampTooLargeException::class]]);

it('rejects malformed ULID strings', function (string $value, string $exception): void {
    expect(fn(): Ulid => Ulid::fromString($value))->toThrow($exception);
})->with([
    ['', Raxos\Security\Error\UlidInvalidLengthException::class],
    [str_repeat('I', 26), Raxos\Security\Error\UlidWrongCharactersException::class],
    [str_repeat('Z', 26), Raxos\Security\Error\UlidTimestampTooLargeException::class],
]);

it('generates cryptographic tokens containing the requested number of bytes', function (bool $urlSafe): void {
    $token = TokenGenerator::generateCryptographicallySecureToken(32, $urlSafe);
    expect(strlen($urlSafe ? Base64::decodeUrlSafe($token) : Base64::decode($token)))->toBe(32);
    if ($urlSafe) {
        expect($token)->toMatch('/^[A-Za-z0-9_-]+$/');
    }
})->with([false, true]);
