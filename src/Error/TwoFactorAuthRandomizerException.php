<?php
declare(strict_types=1);

namespace Raxos\Security\Error;

use Random\RandomException;
use Raxos\Contract\Security\TwoFactorAuthExceptionInterface;
use Raxos\Error\Exception;

/**
 * Class TwoFactorAuthRandomizerException
 *
 * @author Bas Milius <bas@mili.us>
 * @package Raxos\Security\Error
 * @since 2.0.0
 */
final class TwoFactorAuthRandomizerException extends Exception implements TwoFactorAuthExceptionInterface
{

    /**
     * TwoFactorAuthRandomizerException constructor.
     *
     * @param RandomException $err
     *
     * @author Bas Milius <bas@mili.us>
     * @since 2.0.0
     */
    public function __construct(
        public readonly RandomException $err
    )
    {
        parent::__construct(
            'two_factor_auth_randomizer',
            'Could not generate a strong enough random value.',
            previous: $err
        );
    }

}
