<?php
declare(strict_types=1);

namespace Raxos\Security\Error;

use Raxos\Contract\Security\TwoFactorAuthExceptionInterface;
use Raxos\Error\Exception;

/**
 * Class TwoFactorAuthInvalidDataException
 *
 * @author Bas Milius <bas@mili.us>
 * @package Raxos\Security\Error
 * @since 2.0.0
 */
final class TwoFactorAuthInvalidDataException extends Exception implements TwoFactorAuthExceptionInterface
{

    /**
     * TwoFactorAuthInvalidDataException constructor.
     *
     * @param string $message
     *
     * @author Bas Milius <bas@mili.us>
     * @since 2.0.0
     */
    public function __construct(string $message)
    {
        parent::__construct(
            'two_factor_auth_invalid_data',
            $message,
        );
    }

}
