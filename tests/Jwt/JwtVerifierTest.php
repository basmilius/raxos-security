<?php
declare(strict_types=1);

use Psr\Clock\ClockInterface;
use Raxos\Error\InvalidArgumentException;
use Raxos\Security\Error\JwtExpiredException;
use Raxos\Security\Error\JwtNotYetValidException;
use Raxos\Security\Jwt\Jwt;
use Raxos\Security\Jwt\JwtAlgorithm;
use Raxos\Security\Jwt\JwtVerificationKey;
use Raxos\Security\Jwt\JwtVerificationPolicy;
use Raxos\Security\Jwt\JwtVerifier;

covers(JwtVerifier::class, JwtVerificationPolicy::class, JwtVerificationKey::class);

function verifierClock(int $time): ClockInterface
{
    return new readonly class($time) implements ClockInterface {
        public function __construct(private int $time)
        {
        }

        public function now(): DateTimeImmutable
        {
            return new DateTimeImmutable('@' . $this->time);
        }
    };
}

it('verifies independent policies without changing global JWT time or leeway', function (): void {
    $beforeTime = Jwt::$currentTime;
    $beforeLeeway = Jwt::$leeway;
    $key = new JwtVerificationKey('unit-secret');
    $policy = new JwtVerificationPolicy(['one' => $key], issuer: 'https://issuer.example.org', audience: 'service');
    $token = Jwt::encode(['exp' => 110, 'iss' => $policy->issuer, 'aud' => ['other', 'service']], $key->key, keyId: 'one');
    expect(new JwtVerifier($policy, verifierClock(100))->verify($token)['exp'])->toBe(110);
    expect(fn() => new JwtVerifier($policy, verifierClock(110))->verify($token))->toThrow(JwtExpiredException::class);
    expect(Jwt::$currentTime)->toBe($beforeTime)->and(Jwt::$leeway)->toBe($beforeLeeway);
});

it('rejects invalid issuer audience and missing expiration', function (array $claims): void {
    $policy = new JwtVerificationPolicy(['one' => new JwtVerificationKey('unit-secret')], issuer: 'issuer', audience: 'service');
    $token = Jwt::encode($claims, 'unit-secret');
    expect(fn() => new JwtVerifier($policy, verifierClock(100))->verify($token))->toThrow(InvalidArgumentException::class);
})->with([[['exp' => 200, 'iss' => 'wrong', 'aud' => 'service']], [['exp' => 200, 'iss' => 'issuer', 'aud' => 'wrong']], [['iss' => 'issuer', 'aud' => 'service']]]);

it('rejects an unknown single-key identifier and an algorithm not bound to its key', function (): void {
    $policy = new JwtVerificationPolicy(['one' => new JwtVerificationKey('unit-secret')]);
    $verifier = new JwtVerifier($policy, verifierClock(100));
    expect(fn() => $verifier->verify(Jwt::encode(['exp' => 200], 'unit-secret', keyId: 'unknown')))->toThrow(InvalidArgumentException::class);
    expect(fn() => $verifier->verify(Jwt::encode(['exp' => 200], 'unit-secret', JwtAlgorithm::HS512, 'one')))->toThrow(InvalidArgumentException::class);
});

it('rejects malformed NumericDates without PHP conversion warnings', function (mixed $value): void {
    expect(fn() => Jwt::decodeAt(Jwt::encode(['exp' => $value], 'secret'), ['secret'], [JwtAlgorithm::HS256], 100))->toThrow(InvalidArgumentException::class);
})->with([['invalid'], [null], [[100]], [true]]);

it('rejects invalid audience lists even if one member matches', function (array $audience): void {
    $policy = new JwtVerificationPolicy(['one' => new JwtVerificationKey('secret')], audience: 'service');
    $token = Jwt::encode(['exp' => 200, 'aud' => $audience], 'secret');
    expect(fn() => new JwtVerifier($policy, verifierClock(100))->verify($token))->toThrow(InvalidArgumentException::class);
})->with([[['service', 7]], [['service', []]], [['named' => 'service']]]);

it('applies clock skew at the NumericDate boundary including fractional seconds', function (string $claim, float $value, ?string $error): void {
    $policy = new JwtVerificationPolicy(['one' => new JwtVerificationKey('secret')], leeway: 5);
    $verifier = new JwtVerifier($policy, verifierClock(100));
    $claims = ['exp' => 200, $claim => $value];
    $token = Jwt::encode($claims, 'secret', keyId: 'one');

    if ($error !== null) {
        expect(fn() => $verifier->verify($token))->toThrow($error);

        return;
    }

    expect($verifier->verify($token)[$claim])->toEqual($value);
})->with([
    'expired at the allowed boundary' => ['exp', 95.0, JwtExpiredException::class],
    'fractionally inside the expiration window' => ['exp', 95.5, null],
    'not-before at the allowed boundary' => ['nbf', 105.0, null],
    'not-before beyond the allowed boundary' => ['nbf', 105.5, JwtNotYetValidException::class],
    'issued-at at the allowed boundary' => ['iat', 105.0, null],
    'issued-at beyond the allowed boundary' => ['iat', 105.5, JwtNotYetValidException::class]
]);
