<?php
declare(strict_types=1);

use Raxos\Error\InvalidArgumentException;
use Raxos\Security\Error\TwoFactorAuthInvalidDataException;
use Raxos\Security\TwoFactor\{TwoFactorAuth, TwoFactorAuthAlgorithm};

covers(TwoFactorAuth::class);

it('matches the RFC6238 SHA1 vectors before and after 2038', function (int $time, string $expected): void {
    // https://www.rfc-editor.org/rfc/rfc6238#appendix-B
    expect(new TwoFactorAuth(digits: 8)->generateCode('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', $time))->toBe($expected);
})->with([[59, '94287082'], [1111111109, '07081804'], [1111111111, '14050471'], [1234567890, '89005924'], [2000000000, '69279037'], [20000000000, '65353130']]);

it('verifies current and adjacent periods but rejects invalid codes', function (): void {
    $auth = new TwoFactorAuth(period: 1_000_000);
    $secret = $auth->createSecret();
    expect(strlen($secret))->toBe(32)
        ->and($secret)->toMatch('/^[A-Z2-7]+$/')
        ->and($auth->verifyCode($secret, $auth->generateCode($secret)))->toBeTrue()
        ->and($auth->verifyCode($secret, $auth->generateCode($secret, time() - 1_000_000)))->toBeTrue()
        ->and($auth->verifyCode($secret, 'not-an-otp'))->toBeFalse();
});

it('encodes provisioning labels and settings in the OTP URI', function (): void {
    $uri = new TwoFactorAuth('Raxos & Co', 8, 60, TwoFactorAuthAlgorithm::SHA256)->generateQrData('ABC234', 'user@example.org');
    expect($uri)->toStartWith('otpauth://totp/user%40example.org?');
    parse_str(parse_url($uri, PHP_URL_QUERY), $query);
    expect($query)->toBe(['secret' => 'ABC234', 'issuer' => 'Raxos & Co', 'period' => '60', 'algorithm' => 'SHA256', 'digits' => '8']);
});

it('rejects invalid two-factor settings', function (int $digits, int $period): void {
    expect(fn(): TwoFactorAuth => new TwoFactorAuth(digits: $digits, period: $period))->toThrow(InvalidArgumentException::class);
})->with([[0, 30], [-1, 30], [6, 0], [6, -1]]);

it('rejects malformed or empty two-factor secrets', function (string $secret): void {
    expect(fn(): string => new TwoFactorAuth()->generateCode($secret, 59))->toThrow(TwoFactorAuthInvalidDataException::class);
})->with(['', 'INVALID!']);

it('matches the RFC6238 SHA256 and SHA512 vectors', function (TwoFactorAuthAlgorithm $algorithm, string $secret, int $time, string $expected): void {
    expect(new TwoFactorAuth(digits: 8, algorithm: $algorithm)->generateCode($secret, $time))->toBe($expected);
})->with([
    [TwoFactorAuthAlgorithm::SHA256, 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA', 59, '46119246'],
    [TwoFactorAuthAlgorithm::SHA256, 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA', 1111111109, '68084774'],
    [TwoFactorAuthAlgorithm::SHA256, 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA', 1111111111, '67062674'],
    [TwoFactorAuthAlgorithm::SHA256, 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA', 1234567890, '91819424'],
    [TwoFactorAuthAlgorithm::SHA256, 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA', 2000000000, '90698825'],
    [TwoFactorAuthAlgorithm::SHA256, 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA', 20000000000, '77737706'],
    [TwoFactorAuthAlgorithm::SHA512, 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA', 59, '90693936'],
    [TwoFactorAuthAlgorithm::SHA512, 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA', 1111111109, '25091201'],
    [TwoFactorAuthAlgorithm::SHA512, 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA', 1111111111, '99943326'],
    [TwoFactorAuthAlgorithm::SHA512, 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA', 1234567890, '93441116'],
    [TwoFactorAuthAlgorithm::SHA512, 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA', 2000000000, '38618901'],
    [TwoFactorAuthAlgorithm::SHA512, 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA', 20000000000, '47863826']
]);
