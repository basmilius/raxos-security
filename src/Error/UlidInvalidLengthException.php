<?php
declare(strict_types=1);

namespace Raxos\Security\Error;

use Raxos\Contract\Security\UlidExceptionInterface;
use Raxos\Error\Exception;

/**
 * Class UlidInvalidLengthException
 *
 * @author Bas Milius <bas@mili.us>
 * @package Raxos\Security\Error
 * @since 2.0.0
 */
final class UlidInvalidLengthException extends Exception implements UlidExceptionInterface
{

    /**
     * UlidInvalidLengthException constructor.
     *
     * @param string $value
     *
     * @author Bas Milius <bas@mili.us>
     * @since 2.0.0
     */
    public function __construct(
        public readonly string $value
    )
    {
        parent::__construct(
            'ulid_invalid_length',
            "Invalid length for ULID string '{$this->value}'."
        );
    }

}
