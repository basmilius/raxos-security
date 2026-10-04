<?php
declare(strict_types=1);

namespace Raxos\Security\Jwt;

use Raxos\Error\InvalidArgumentException;

/**
 * Class JwtVerificationPolicy
 *
 * Immutable constraints for one verifier instance.
 *
 * @author Bas Milius <bas@mili.us>
 * @package Raxos\Security\Jwt
 * @since 3.3.0
 */
final readonly class JwtVerificationPolicy
{
    /**
     * Defines instance-local key selection, required claims and allowed clock skew in seconds.
     *
     * @param array<string, JwtVerificationKey> $keys
     * @param string|null $issuer
     * @param string|null $audience
     * @param int $leeway
     * @param bool $requireExpiration
     * @throws InvalidArgumentException
     * @author Bas Milius <bas@mili.us>
     * @since 3.3.0
     */
    public function __construct(
        public array $keys,
        public ?string $issuer = null,
        public ?string $audience = null,
        public int $leeway = 0,
        public bool $requireExpiration = true
    )
    {
        if ($keys === [] || $leeway < 0) {
            throw new InvalidArgumentException('Verification requires keys and non-negative leeway.');
        }

        foreach ($keys as $key) {
            if (!$key instanceof JwtVerificationKey) {
                throw new InvalidArgumentException('Every verification key must bind its algorithm.');
            }
        }
    }
}
