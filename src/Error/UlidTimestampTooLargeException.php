<?php
declare(strict_types=1);

namespace Raxos\Security\Error;

use Raxos\Contract\Security\UlidExceptionInterface;
use Raxos\Error\Exception;

/**
 * Class UlidTimestampTooLargeException
 *
 * @author Bas Milius <bas@mili.us>
 * @package Raxos\Security\Error
 * @since 2.0.0
 */
final class UlidTimestampTooLargeException extends Exception implements UlidExceptionInterface
{

    /**
     * UlidTimestampTooLargeException constructor.
     *
     * @author Bas Milius <bas@mili.us>
     * @since 2.0.0
     */
    public function __construct()
    {
        parent::__construct(
            'ulid_invalid_length',
            'Timestamp too large for ULID.'
        );
    }

}
