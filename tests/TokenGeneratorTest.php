<?php
declare(strict_types=1);

use Raxos\Security\{Base64, TokenGenerator};

covers(TokenGenerator::class);

it('generates cryptographic tokens containing the requested number of bytes', function (bool $urlSafe): void {
    $token = TokenGenerator::generateCryptographicallySecureToken(32, $urlSafe);
    expect(strlen($urlSafe ? Base64::decodeUrlSafe($token) : Base64::decode($token)))->toBe(32);
    if ($urlSafe) {
        expect($token)->toMatch('/^[A-Za-z0-9_-]+$/');
    }
})->with([false, true]);

it('produces independent tokens and rejects nonpositive byte counts', function (): void {
    expect(TokenGenerator::generateCryptographicallySecureToken(32))->not->toBe(TokenGenerator::generateCryptographicallySecureToken(32))
        ->and(fn () => TokenGenerator::generateCryptographicallySecureToken(0))->toThrow(ValueError::class)
        ->and(fn () => TokenGenerator::generateCryptographicallySecureToken(-1))->toThrow(ValueError::class);
});
