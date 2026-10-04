<?php
declare(strict_types=1);

namespace Raxos\Security\Jwt;

use JsonException;
use Psr\Clock\ClockInterface;
use Raxos\Contract\Security\JwtExceptionInterface;
use Raxos\Error\InvalidArgumentException;
use Raxos\Foundation\Util\SystemClock;
use Raxos\Security\Base64;
use function array_all;
use function array_is_list;
use function array_values;
use function count;
use function explode;
use function in_array;
use function is_array;
use function is_string;
use function json_decode;
use const JSON_THROW_ON_ERROR;

/**
 * Class JwtVerifier
 *
 * Instance-local verification with explicit claim policy and clock.
 *
 * @author Bas Milius <bas@mili.us>
 * @package Raxos\Security\Jwt
 * @since 3.3.0
 */
final readonly class JwtVerifier
{
    /**
     * Keeps claim policy and clock local to this verifier, without changing JWT static configuration.
     *
     * @param JwtVerificationPolicy $policy
     * @param ClockInterface $clock
     * @author Bas Milius <bas@mili.us>
     * @since 3.3.0
     */
    public function __construct(
        public JwtVerificationPolicy $policy,
        public ClockInterface $clock = new SystemClock()
    )
    {
    }

    /**
     * Selects an allowed key, verifies its bound algorithm and validates time, issuer and audience claims.
     *
     * @param string $token
     * @return array<string, mixed>
     * @throws InvalidArgumentException|JwtExceptionInterface
     * @author Bas Milius <bas@mili.us>
     * @since 3.3.0
     */
    public function verify(string $token): array
    {
        $segments = explode('.', $token);

        if (count($segments) !== 3) {
            throw new InvalidArgumentException('Invalid JWT segments.');
        }

        try {
            $header = json_decode(Base64::decodeUrlSafe($segments[0]), true, flags: JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            throw new InvalidArgumentException('Invalid JWT header.');
        }

        if (!is_array($header) || !is_string($header['alg'] ?? null)) {
            throw new InvalidArgumentException('Missing JWT algorithm.');
        }

        if (isset($header['kid'])) {
            if (!is_string($header['kid']) || !isset($this->policy->keys[$header['kid']])) {
                throw new InvalidArgumentException('Unknown JWT key identifier.');
            }

            $key = $this->policy->keys[$header['kid']];
        } elseif (count($this->policy->keys) === 1) {
            $key = array_values($this->policy->keys)[0];
        } else {
            throw new InvalidArgumentException('A JWT key identifier is required.');
        }

        $claims = Jwt::decodeAt($token, [$key->key], [$key->algorithm], $this->clock->now()->getTimestamp(), $this->policy->leeway);

        if ($this->policy->requireExpiration && !isset($claims['exp'])) {
            throw new InvalidArgumentException('JWT expiration is required.');
        }

        if ($this->policy->issuer !== null && ($claims['iss'] ?? null) !== $this->policy->issuer) {
            throw new InvalidArgumentException('JWT issuer does not match.');
        }

        if ($this->policy->audience !== null) {
            $audience = $claims['aud'] ?? null;

            $validString = is_string($audience);
            $validList = is_array($audience)
                && array_is_list($audience)
                && array_all($audience, static fn(mixed $value): bool => is_string($value));

            if (!$validString && !$validList) {
                throw new InvalidArgumentException('JWT audience is invalid.');
            }

            if (!in_array($this->policy->audience, is_array($audience) ? $audience : [$audience], true)) {
                throw new InvalidArgumentException('JWT audience does not match.');
            }
        }

        return $claims;
    }
}
