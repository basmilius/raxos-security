<?php
declare(strict_types=1);

use Raxos\Security\Error\JwtEncryptionException;
use Raxos\Security\Jwt\JwtAlgorithm;

covers(JwtAlgorithm::class);

it('signs HMAC messages using the specified hash and rejects changed data', function (JwtAlgorithm $algorithm, string $hash): void {
    $signature = $algorithm->sign('secret', 'message');
    expect(bin2hex($signature))->toBe(hash_hmac($hash, 'message', 'secret'))
        ->and($algorithm->verify('secret', $signature, 'message'))->toBeTrue()
        ->and($algorithm->verify('other', $signature, 'message'))->toBeFalse()
        ->and($algorithm->verify('secret', $signature, 'changed'))->toBeFalse()
        ->and($algorithm->verify('secret', '', 'message'))->toBeFalse();
})->with([[JwtAlgorithm::HS256, 'sha256'], [JwtAlgorithm::HS384, 'sha384'], [JwtAlgorithm::HS512, 'sha512']]);

it('signs and verifies RSA messages with each supported digest', function (JwtAlgorithm $algorithm): void {
    $key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
    openssl_pkey_export($key, $private);
    $public = openssl_pkey_get_details($key)['key'];
    $signature = $algorithm->sign($private, 'message');
    expect($algorithm->verify($public, $signature, 'message'))->toBeTrue()
        ->and($algorithm->verify($public, $signature, 'changed'))->toBeFalse();
})->with([JwtAlgorithm::RS256, JwtAlgorithm::RS384, JwtAlgorithm::RS512]);

it('rejects PEM material as a HMAC secret before producing a signature', function (JwtAlgorithm $algorithm): void {
    expect(fn () => $algorithm->sign('-----BEGIN PUBLIC KEY-----', 'message'))->toThrow(JwtEncryptionException::class);
})->with([JwtAlgorithm::HS256, JwtAlgorithm::HS384, JwtAlgorithm::HS512]);

it('reports invalid RSA key material rather than treating it as a failed signature', function (): void {
    set_error_handler(static fn (int $severity, string $message): bool => $severity === E_WARNING && str_starts_with($message, 'openssl_'));
    try {
        expect(fn () => JwtAlgorithm::RS256->sign('invalid', 'message'))->toThrow(JwtEncryptionException::class)
            ->and(fn () => JwtAlgorithm::RS256->verify('invalid', 'signature', 'message'))->toThrow(JwtEncryptionException::class);
    } finally {
        restore_error_handler();
    }
});
