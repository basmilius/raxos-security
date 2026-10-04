<?php
declare(strict_types=1);

namespace Raxos\Security\Jwt;

use SensitiveParameter;

/**
 * Class JwtVerificationKey
 *
 * Binds verification material to one algorithm to prevent cross-algorithm key reuse.
 *
 * @author Bas Milius <bas@mili.us>
 * @package Raxos\Security\Jwt
 * @since 3.3.0
 */
final readonly class JwtVerificationKey
{

    /**
     * Binds the key to one permitted signing algorithm instead of trusting the token header.
     *
     * @param string $key
     * @param JwtAlgorithm $algorithm
     *
     * @author Bas Milius <bas@mili.us>
     * @since 3.3.0
     */
    public function __construct(
        #[SensitiveParameter] public string $key,
        public JwtAlgorithm $algorithm = JwtAlgorithm::HS256
    ) {}

}
