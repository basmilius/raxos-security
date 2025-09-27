<?php
declare(strict_types=1);

namespace Raxos\Security\Error;

use Raxos\Contract\Security\JwtExceptionInterface;
use Raxos\Error\Exception;

/**
 * Class JwtExpiredException
 *
 * @author Bas Milius <bas@mili.us>
 * @package Raxos\Security\Error
 * @since 2.0.0
 */
final class JwtExpiredException extends Exception implements JwtExceptionInterface
{

    /**
     * JwtExpiredException constructor.
     *
     * @author Bas Milius <bas@mili.us>
     * @since 2.0.0
     */
    public function __construct()
    {
        parent::__construct(
            'jwt_expired',
            'The JWT token has expired.'
        );
    }

}
