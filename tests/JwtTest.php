<?php
declare(strict_types=1);

use Raxos\Error\InvalidArgumentException;
use Raxos\Security\Base64;
use Raxos\Security\Error\JwtEncryptionException;
use Raxos\Security\Error\JwtExpiredException;
use Raxos\Security\Error\JwtInvalidSignatureException;
use Raxos\Security\Error\JwtNotYetValidException;
use Raxos\Security\Jwt\Jwt;
use Raxos\Security\Jwt\JwtAlgorithm;

beforeEach(function (): void {
    Jwt::$currentTime = 1_000;
    Jwt::$leeway = 0;
});

afterEach(function (): void {
    Jwt::$currentTime = null;
    Jwt::$leeway = 0;
});

it('round trips HMAC tokens with an explicitly permitted algorithm', function (JwtAlgorithm $algorithm): void {
    $token = Jwt::encode(['sub' => 'passly', 'exp' => 1_100], 'secret', $algorithm);
    expect(Jwt::decode($token, ['secret'], [$algorithm]))->toBe(['sub' => 'passly', 'exp' => 1_100]);
})->with([JwtAlgorithm::HS256, JwtAlgorithm::HS384, JwtAlgorithm::HS512]);

it('keeps the HS256 default used by Passly', function (): void {
    expect(Jwt::decode(Jwt::encode(['sub' => 'wallet'], 'secret'), ['secret']))->toBe(['sub' => 'wallet']);
});

it('rejects asymmetric public keys as HMAC secrets even in a mixed allowlist', function (): void {
    $private = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
    $public = openssl_pkey_get_details($private)['key'];
    $message = Base64::encodeUrlSafe('{"alg":"HS256"}') . '.' . Base64::encodeUrlSafe('{"sub":"forged"}');
    $forged = $message . '.' . Base64::encodeUrlSafe(hash_hmac('sha256', $message, $public, true));
    expect(fn() => Jwt::decode($forged, [$public], [JwtAlgorithm::HS256, JwtAlgorithm::RS256]))->toThrow(JwtEncryptionException::class);
});

it('requires RSA to be explicitly allowed', function (): void {
    $resource = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
    openssl_pkey_export($resource, $private);
    $public = openssl_pkey_get_details($resource)['key'];
    $token = Jwt::encode(['sub' => 42], $private, JwtAlgorithm::RS256);
    expect(Jwt::decode($token, [$public], [JwtAlgorithm::RS256]))->toBe(['sub' => 42]);
    expect(fn() => Jwt::decode($token, [$public]))->toThrow(InvalidArgumentException::class);
});

it('rejects an empty algorithm policy', function (): void {
    expect(fn() => Jwt::decode(Jwt::encode([], 'secret'), ['secret'], []))->toThrow(InvalidArgumentException::class);
});

it('verifies signatures before accepting claims', function (): void {
    expect(fn() => Jwt::decode(Jwt::encode(['sub' => 1], 'other'), ['secret']))->toThrow(JwtInvalidSignatureException::class);
});

it('enforces expiration and not before', function (): void {
    expect(fn() => Jwt::decode(Jwt::encode(['exp' => 1_000], 'secret'), ['secret']))->toThrow(JwtExpiredException::class);
    expect(fn() => Jwt::decode(Jwt::encode(['nbf' => 1_001], 'secret'), ['secret']))->toThrow(JwtNotYetValidException::class);
    Jwt::$leeway = 1;
    expect(Jwt::decode(Jwt::encode(['nbf' => 1_001], 'secret'), ['secret']))->toBe(['nbf' => 1_001]);
});

it('rejects scalar JWT segments', function (): void {
    $message = Base64::encodeUrlSafe('42') . '.' . Base64::encodeUrlSafe('true');
    $token = $message . '.' . Base64::encodeUrlSafe(hash_hmac('sha256', $message, 'secret', true));
    expect(fn() => Jwt::decode($token, ['secret']))->toThrow(InvalidArgumentException::class);
});

it('selects the configured key by its header id', function (): void {
    $token = Jwt::encode(['sub' => 42], 'active-secret', keyId: 'active');
    expect(Jwt::decode($token, ['previous' => 'old-secret', 'active' => 'active-secret']))->toBe(['sub' => 42]);
});

it('rejects missing unknown or malformed key ids with multiple keys', function (array $headers): void {
    $token = Jwt::encode(['sub' => 42], 'active-secret', headers: $headers);
    expect(fn(): array => Jwt::decode($token, ['previous' => 'old-secret', 'active' => 'active-secret']))->toThrow(InvalidArgumentException::class);
})->with([[[]], [['kid' => 'unknown']], [['kid' => ['active']]], [['kid' => 0]]]);
