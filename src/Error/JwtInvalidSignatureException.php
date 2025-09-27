<?php
declare(strict_types=1);

namespace Raxos\Security\Error;

use Raxos\Contract\Security\JwtExceptionInterface;
use Raxos\Error\Exception;

/**
 * Class JwtInvalidSignatureException
 *
 * @author Bas Milius <bas@mili.us>
 * @package Raxos\Security\Error
 * @since 2.0.0
 */
final class JwtInvalidSignatureException extends Exception implements JwtExceptionInterface
{

    /**
     * JwtInvalidSignatureException constructor.
     *
     * @author Bas Milius <bas@mili.us>
     * @since 2.0.0
     */
    public function __construct()
    {
        parent::__construct(
            'jwt_invalid_signature',
            'The JWT token has an invalid signature.'
        );
    }

}
