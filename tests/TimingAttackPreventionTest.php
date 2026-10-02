<?php
declare(strict_types=1);

use Raxos\Security\TimingAttackPrevention;

covers(TimingAttackPrevention::class);

it('delays a fast operation until the configured minimum duration', function (): void {
    $prevention = new TimingAttackPrevention(20);
    $start = hrtime(true);
    $prevention->begin();
    $prevention->end();
    expect((hrtime(true) - $start) / 1e6)->toBeGreaterThanOrEqual(19);
});

it('allows a zero delay and an operation already slower than the configured duration', function (): void {
    foreach ([0, 1] as $milliseconds) {
        $prevention = new TimingAttackPrevention($milliseconds);
        $prevention->begin();
        if ($milliseconds > 0) {
            usleep(2000);
        }
        expect(fn () => $prevention->end())->not->toThrow(Throwable::class);
    }
});
