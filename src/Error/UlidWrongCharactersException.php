<?php
declare(strict_types=1);

namespace Raxos\Security\Error;

use Raxos\Contract\Security\UlidExceptionInterface;
use Raxos\Error\Exception;

/**
 * Class UlidWrongCharactersException
 *
 * @author Bas Milius <bas@mili.us>
 * @package Raxos\Security\Error
 * @since 2.0.0
 */
final class UlidWrongCharactersException extends Exception implements UlidExceptionInterface
{

    /**
     * UlidWrongCharactersException constructor.
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
            'ulid_wrong_characters',
            "Wrong characters in ULID string '{$this->value}'."
        );
    }

}
