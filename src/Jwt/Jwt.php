<?php
declare(strict_types=1);

namespace Raxos\Security\Jwt;

use JsonException;
use Raxos\Contract\Security\JwtExceptionInterface;
use Raxos\Error\InvalidArgumentException;
use Raxos\Security\Base64;
use Raxos\Security\Error\JwtEncodingException;
use Raxos\Security\Error\JwtExpiredException;
use Raxos\Security\Error\JwtInvalidSignatureException;
use Raxos\Security\Error\JwtNotYetValidException;
use Raxos\Security\Error\JwtNullException;
use Raxos\Security\Error\JwtUnsupportedException;
use function array_key_exists;
use function array_shift;
use function count;
use function explode;
use function implode;
use function is_array;
use function is_finite;
use function is_float;
use function is_int;
use function is_string;
use function json_decode;
use function json_encode;
use function sprintf;
use const JSON_BIGINT_AS_STRING;
use const JSON_THROW_ON_ERROR;

/**
 * Class Jwt
 *
 * @author Bas Milius <bas@mili.us>
 * @package Raxos\Security\Jwt
 * @since 2.0.0
 */
final class Jwt
{

    /**
     * Provides the legacy process-wide clock override; instance verifiers use their own clock.
     *
     * @var ?int
     * @author Bas Milius <bas@mili.us>
     * @since 2.0.0
     */
    public static ?int $currentTime = null;

    /**
     * Provides legacy process-wide clock skew in seconds; instance verifiers use their own policy.
     *
     * @var int
     * @author Bas Milius <bas@mili.us>
     * @since 2.0.0
     */
    public static int $leeway = 0;

    /**
     * Decodes a JWT string into an array.
     *
     * @param string $jwt
     * @param string[] $keys
     * @param JwtAlgorithm[] $allowedAlgorithms
     *
     * @return array
     * @throws InvalidArgumentException
     * @throws JwtExceptionInterface
     * @author Bas Milius <bas@mili.us>
     * @since 2.0.0
     *
     * @see Jwt::jsonDecode()
     * @see Jwt::urlsafeB64Decode()
     */
    public static function decode(
        string $jwt,
        array $keys,
        array $allowedAlgorithms = [JwtAlgorithm::HS256]
    ): array
    {
        return self::decodeAt($jwt, $keys, $allowedAlgorithms, self::$currentTime ?? time(), self::$leeway);
    }

    /**
     * Verifies against explicit time and leeway without changing shared state.
     *
     * @param string $jwt
     * @param array<string|int, string> $keys
     * @param JwtAlgorithm[] $allowedAlgorithms
     * @param int $currentTime
     * @param int $leeway
     *
     * @return array
     * @throws InvalidArgumentException|JwtExceptionInterface
     * @author Bas Milius <bas@mili.us>
     * @since 3.3.0
     */
    public static function decodeAt(
        string $jwt,
        array $keys,
        array $allowedAlgorithms,
        int $currentTime,
        int $leeway = 0
    ): array
    {
        if ($leeway < 0) {
            throw new InvalidArgumentException('JWT leeway cannot be negative.');
        }

        if ($allowedAlgorithms === []) {
            throw new InvalidArgumentException('At least one allowed algorithm is required.');
        }

        if (empty($keys)) {
            throw new InvalidArgumentException('At least one key is required.');
        }

        $segments = explode('.', $jwt);

        if (count($segments) !== 3) {
            throw new InvalidArgumentException('The number of JWT segments is invalid.');
        }

        [$header64, $payload64, $signature64] = $segments;

        $header = self::jsonDecode(Base64::decodeUrlSafe($header64));
        $payload = self::jsonDecode(Base64::decodeUrlSafe($payload64));
        $signature = Base64::decodeUrlSafe($signature64);

        if (!is_array($header) || !is_array($payload) || empty($signature)) {
            throw new InvalidArgumentException('Invalid encoding of segment.');
        }

        if (!isset($header['alg']) || !is_string($header['alg'])) {
            throw new InvalidArgumentException('Unknown algorithm.');
        }

        $algorithm = JwtAlgorithm::tryFrom($header['alg']);

        if ($algorithm === null) {
            throw new JwtUnsupportedException('Algorithm not supported.');
        }

        if (!in_array($algorithm, $allowedAlgorithms, true)) {
            throw new InvalidArgumentException(sprintf('Algorithm "%s" not allowed.', $algorithm->value));
        }

        if (count($keys) > 1) {
            if (isset($header['kid'])) {
                if (is_string($header['kid']) && isset($keys[$header['kid']])) {
                    $key = $keys[$header['kid']];
                } else {
                    throw new InvalidArgumentException('Key ID (kid) is invalid, key does not exist.');
                }
            } else {
                throw new InvalidArgumentException('Key ID (kid) is missing in the header.');
            }
        } else {
            $key = array_shift($keys);
        }

        if (!$algorithm->verify($key, $signature, sprintf('%s.%s', $header64, $payload64))) {
            throw new JwtInvalidSignatureException();
        }

        foreach (['exp', 'nbf', 'iat'] as $claim) {
            if (array_key_exists($claim, $payload) && ((!is_int($payload[$claim]) && !is_float($payload[$claim])) || !is_finite((float)$payload[$claim]))) {
                throw new InvalidArgumentException("JWT {$claim} must be a finite NumericDate.");
            }
        }

        if (array_key_exists('nbf', $payload) && $payload['nbf'] > ($currentTime + $leeway)) {
            throw new JwtNotYetValidException();
        }

        if (array_key_exists('iat', $payload) && $payload['iat'] > ($currentTime + $leeway)) {
            throw new JwtNotYetValidException();
        }

        if (array_key_exists('exp', $payload) && ($currentTime - $leeway) >= $payload['exp']) {
            throw new JwtExpiredException();
        }

        return $payload;
    }

    /**
     * Converts and signs an array into a JWT string.
     *
     * @param array $payload
     * @param string $key
     * @param JwtAlgorithm $algorithm
     * @param string|null $keyId
     * @param array $headers
     *
     * @return string
     * @throws JwtExceptionInterface
     * @author Bas Milius <bas@mili.us>
     * @since 2.0.0
     *
     * @see Jwt::jsonEncode()
     * @see Jwt::urlsafeB64Encode()
     */
    public static function encode(
        array $payload,
        string $key,
        JwtAlgorithm $algorithm = JwtAlgorithm::HS256,
        ?string $keyId = null,
        array $headers = []
    ): string
    {
        $headers['typ'] = 'JWT';
        $headers['alg'] = $algorithm->value;

        if ($keyId !== null) {
            $headers['kid'] = $keyId;
        }

        $segments = [];
        $segments[] = Base64::encodeUrlSafe(self::jsonEncode($headers));
        $segments[] = Base64::encodeUrlSafe(self::jsonEncode($payload));

        $plainToken = implode('.', $segments);

        $signature = $algorithm->sign($key, $plainToken);
        $segments[] = Base64::encodeUrlSafe($signature);

        return implode('.', $segments);
    }

    /**
     * Decodes a JSON string into an array.
     *
     * @param string $input
     *
     * @return mixed
     * @throws JwtExceptionInterface
     * @author Bas Milius <bas@mili.us>
     * @since 2.0.0
     */
    private static function jsonDecode(string $input): mixed
    {
        try {
            $data = json_decode($input, true, 512, JSON_BIGINT_AS_STRING | JSON_THROW_ON_ERROR);

            if ($data === null && $input !== 'null') {
                throw new JwtNullException();
            }

            return $data;
        } catch (JsonException $err) {
            throw new JwtEncodingException($err);
        }
    }

    /**
     * Encodes an array into a JSON string.
     *
     * @param mixed $data
     *
     * @return string
     * @throws JwtExceptionInterface
     * @author Bas Milius <bas@mili.us>
     * @since 2.0.0
     */
    private static function jsonEncode(mixed $data): string
    {
        try {
            $json = json_encode($data, JSON_THROW_ON_ERROR);

            if ($json === 'null' && $data !== null) {
                throw new JwtNullException();
            }

            return $json;
        } catch (JsonException $err) {
            throw new JwtEncodingException($err);
        }
    }

}
