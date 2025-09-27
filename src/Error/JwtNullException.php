<?php
declare(strict_types=1);

namespace Raxos\Security\Error;

use Raxos\Contract\Security\JwtExceptionInterface;
use Raxos\Error\Exception;

/**
 * Class JwtNullException
 *
 * @author Bas Milius <bas@mili.us>
 * @package Raxos\Security\Error
 * @since 2.0.0
 */
final class JwtNullException extends Exception implements JwtExceptionInterface
{

    /**
     * JwtNullException constructor.
     *
     * @author Bas Milius <bas@mili.us>
     * @since 2.0.0
     */
    public function __construct()
    {
        parent::__construct(
            'jwt_null',
            'NULL result with non-NULL data.'
        );
    }

}
