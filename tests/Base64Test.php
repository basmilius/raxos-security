<?php
declare(strict_types=1);

use Raxos\Security\{Base64};

covers(Base64::class);

it('preserves binary and falsey input in every Base64 variant', function (string $value): void {
    expect(Base64::decode(Base64::encode($value)))->toBe($value)
        ->and(Base64::decodeUrlSafe(Base64::encodeUrlSafe($value)))->toBe($value)
        ->and(Base64::decodeShuffle(Base64::encodeShuffle($value, 3), 3))->toBe($value);
})->with(['', '0', "\0\xff\xfe\0", 'Hello world!', 'é😀', str_repeat('raxos', 100)]);

it('rejects malformed Base64', function (string $value): void {
    expect(fn(): string => Base64::decode($value))->toThrow(InvalidArgumentException::class);
})->with(['%%%', 'a', 'YWJj!']);

it('matches known Base64 vectors and removes URL padding', function (string $plain, string $encoded): void {
    expect(Base64::encode($plain))->toBe($encoded)
        ->and(Base64::decode($encoded))->toBe($plain)
        ->and(Base64::encodeUrlSafe($plain))->toBe(rtrim($encoded, '='));
})->with([['f', 'Zg=='], ['fo', 'Zm8='], ['foo', 'Zm9v'], ['foobar', 'Zm9vYmFy']]);

it('rejects invalid URL and shuffled encodings', function (): void {
    expect(fn() => Base64::decodeUrlSafe('%%%'))->toThrow(InvalidArgumentException::class)
        ->and(fn() => Base64::decodeShuffle('%%%'))->toThrow(InvalidArgumentException::class);
});
