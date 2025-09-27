<?php
declare(strict_types=1);

namespace Raxos\Security\Error;

use JsonException;
use Raxos\Contract\Security\JwtExceptionInterface;
use Raxos\Error\Exception;

/**
 * Class JwtEncodingException
 *
 * @author Bas Milius <bas@mili.us>
 * @package Raxos\Security\Error
 * @since 2.0.0
 */
final class JwtEncodingException extends Exception implements JwtExceptionInterface
{

    /**
     * JwtEncodingException constructor.
     *
     * @param JsonException $err
     *
     * @author Bas Milius <bas@mili.us>
     * @since 2.0.0
     */
    public function __construct(
        public readonly JsonException $err
    )
    {
        parent::__construct(
            'jwt_encoding_error',
            'Json encoding/decoding error.',
            previous: $err
        );
    }

}
