<?php
declare(strict_types=1);

namespace Raxos\Security\Error;

use Raxos\Contract\Security\JwtExceptionInterface;
use Raxos\Error\Exception;

/**
 * Class JwtUnsupportedException
 *
 * @author Bas Milius <bas@mili.us>
 * @package Raxos\Security\Error
 * @since 2.0.0
 */
final class JwtUnsupportedException extends Exception implements JwtExceptionInterface
{

    /**
     * JwtUnsupportedException constructor.
     *
     * @param string $message
     *
     * @author Bas Milius <bas@mili.us>
     * @since 2.0.0
     */
    public function __construct(string $message)
    {
        parent::__construct(
            'jwt_encryption_error',
            $message
        );
    }

}
