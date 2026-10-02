<?php
declare(strict_types=1);

use Raxos\Security\{Base64, Hmac};

covers(Hmac::class);

it('matches the RFC4231 HMAC SHA256 vector and detects tampering', function (): void {
    // RFC 4231 section 4.2, test case 1.
    $expected = Base64::encodeUrlSafe(hex2bin('b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7'));
    $key = str_repeat("\x0b", 20);
    expect(Hmac::get('Hi There', $key))->toBe($expected)
        ->and(Hmac::matches($expected, 'Hi There', $key))->toBeTrue()
        ->and(Hmac::matches($expected, 'changed', $key))->toBeFalse()
        ->and(Hmac::matches($expected, 'Hi There', 'other'))->toBeFalse();
});
