<?php
declare(strict_types=1);

use Raxos\Security\Id\{NanoId};

covers(NanoId::class);

it('generates Nano IDs with the requested length and alphabet', function (int $length): void {
    $id = NanoId::generate($length);
    expect(strlen($id))->toBe($length)->and($id)->toMatch('/^[_\-0-9a-zA-Z]+$/');
})->with([1, 16, 21, 64]);

it('rejects non-positive Nano ID lengths', function (int $length): void {
    expect(fn(): string => NanoId::generate($length))->toThrow(Raxos\Error\InvalidArgumentException::class);
})->with([0, -1]);
