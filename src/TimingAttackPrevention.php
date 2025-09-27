<?php
declare(strict_types=1);

namespace Raxos\Security;

use Raxos\Foundation\Util\{Stopwatch, StopwatchUnit};
use function max;
use function usleep;

/**
 * Class TimingAttackPrevention
 *
 * @author Bas Milius <bas@mili.us>
 * @package Raxos\Security
 * @since 2.0.0
 */
final readonly class TimingAttackPrevention
{

    private Stopwatch $stopwatch;

    /**
     * TimingAttackPrevention constructor.
     *
     * @param int $milliseconds
     *
     * @author Bas Milius <bas@mili.us>
     * @since 2.0.0
     */
    public function __construct(
        private int $milliseconds
    )
    {
        $this->stopwatch = new Stopwatch(self::class);
    }

    /**
     * Starts tracking.
     *
     * @return void
     * @author Bas Milius <bas@mili.us>
     * @since 2.0.0
     */
    public function begin(): void
    {
        $this->stopwatch->start();
    }

    /**
     * Ends tracking and sleeps for the remaining time.
     *
     * @return void
     * @author Bas Milius <bas@mili.us>
     * @since 2.0.0
     */
    public function end(): void
    {
        $this->stopwatch->stop();

        $runningTime = $this->stopwatch->as(StopwatchUnit::MILLISECONDS);
        $remainingTime = (int)max(0, $this->milliseconds - $runningTime);

        if ($remainingTime > 0) {
            usleep($remainingTime * 1000);
        }
    }

}
