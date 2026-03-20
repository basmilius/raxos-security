<?php
declare(strict_types=1);

namespace Raxos\Security\Error;

use Raxos\Contract\Security\JwtExceptionInterface;
use Raxos\Error\Exception;

/**
 * Class JwtNotYetValidException
 *
 * @author Bas Milius <bas@mili.us>
 * @package Raxos\Security\Error
 * @since 2.0.0
 */
final class JwtNotYetValidException extends Exception implements JwtExceptionInterface
{

    /**
     * JwtNotYetValidException constructor.
     *
     * @author Bas Milius <bas@mili.us>
     * @since 2.0.0
     */
    public function __construct()
    {
        parent::__construct(
            'jwt_not_yet_valid',
            'The JWT token is not yet valid.'
        );
    }

}
