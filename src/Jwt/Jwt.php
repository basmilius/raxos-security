<?php
declare(strict_types=1);

namespace Raxos\Security\Jwt;

use JsonException;
use Raxos\Contract\Security\JwtExceptionInterface;
use Raxos\Error\InvalidArgumentException;
use Raxos\Security\Base64;
use Raxos\Security\Error\{JwtEncodingException, JwtExpiredException, JwtInvalidSignatureException, JwtNotYetValidException, JwtNullException, JwtUnsupportedException};
use function array_key_exists;
use function array_shift;
use function count;
use function explode;
use function implode;
use function json_decode;
use function json_encode;
use function sprintf;
use function strtoupper;
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

    public static ?int $currentTime = null;

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
    public static function decode(string $jwt, array $keys, array $allowedAlgorithms = []): array
    {
        $currentTime = static::$currentTime ?? time();

        if (empty($keys)) {
            throw new InvalidArgumentException('At least one key is required.');
        }

        $segments = explode('.', $jwt);

        if (count($segments) !== 3) {
            throw new InvalidArgumentException('The number of JWT segments is invalid.');
        }

        [$header64, $payload64, $signature64] = $segments;

        $header = static::jsonDecode(Base64::decodeUrlSafe($header64));
        $payload = static::jsonDecode(Base64::decodeUrlSafe($payload64));
        $signature = Base64::decodeUrlSafe($signature64);

        if ($header === null || $payload === null || empty($signature)) {
            throw new InvalidArgumentException('Invalid encoding of segment.');
        }

        if (!array_key_exists('alg', $header)) {
            throw new InvalidArgumentException('Unknown algorithm.');
        }

        $algorithm = JwtAlgorithm::tryFrom(strtoupper($header['alg']));

        if ($algorithm === null) {
            throw new JwtUnsupportedException('Algorithm not supported.');
        }

        if (count($allowedAlgorithms) > 0 && !in_array($algorithm, $allowedAlgorithms, true)) {
            throw new InvalidArgumentException(sprintf('Algorithm "%s" not allowed.', $algorithm->value));
        }

        if (count($keys) > 1) {
            if (isset($header['kid'])) {
                if (isset($keys[$header['kid']])) {
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

        if (array_key_exists('nbf', $payload) && $payload['nbf'] > ($currentTime + static::$leeway)) {
            throw new JwtNotYetValidException();
        }

        if (array_key_exists('iat', $payload) && $payload['iat'] > ($currentTime + static::$leeway)) {
            throw new JwtNotYetValidException();
        }

        if (array_key_exists('exp', $payload) && ($currentTime - static::$leeway) >= $payload['exp']) {
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
    public static function encode(array $payload, string $key, JwtAlgorithm $algorithm = JwtAlgorithm::HS256, ?string $keyId = null, array $headers = []): string
    {
        $headers['typ'] = 'JWT';
        $headers['alg'] = $algorithm->value;

        if ($keyId !== null) {
            $headers['kid'] = $keyId;
        }

        $segments = [];
        $segments[] = Base64::encodeUrlSafe(static::jsonEncode($headers));
        $segments[] = Base64::encodeUrlSafe(static::jsonEncode($payload));

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
