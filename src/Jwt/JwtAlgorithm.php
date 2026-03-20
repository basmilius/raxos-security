<?php
declare(strict_types=1);

namespace Raxos\Security\Jwt;

use Raxos\Contract\Security\JwtExceptionInterface;
use Raxos\Security\Error\{JwtEncryptionException, JwtUnsupportedException};
use function hash_equals;
use function hash_hmac;
use function openssl_error_string;
use function openssl_sign;
use function openssl_verify;

/**
 * Enum JwtAlgorithm
 *
 * @author Bas Milius <bas@mili.us>
 * @package Raxos\Security\Jwt
 * @since 2.0.0
 */
enum JwtAlgorithm: string
{
    case HS256 = 'HS256';
    case HS384 = 'HS384';
    case HS512 = 'HS512';
    case RS256 = 'RS256';
    case RS384 = 'RS384';
    case RS512 = 'RS512';

    /**
     * Sign the given message with the given key.
     *
     * @param string $key
     * @param string $message
     *
     * @return string
     * @throws JwtExceptionInterface
     * @author Bas Milius <bas@mili.us>
     * @since 2.0.0
     */
    public function sign(string $key, string $message): string
    {
        $algorithm = match ($this) {
            self::HS256, self::RS256 => 'sha256',
            self::HS384, self::RS384 => 'sha384',
            self::HS512, self::RS512 => 'sha512'
        };

        switch ($this) {
            case self::HS256:
            case self::HS384:
            case self::HS512:
                return hash_hmac($algorithm, $message, $key, binary: true);

            case self::RS256:
            case self::RS384:
            case self::RS512:
                if (!openssl_sign($message, $signature, $key, $algorithm)) {
                    throw new JwtEncryptionException('Unable to sign the message.');
                }

                return $signature;
        }

        throw new JwtUnsupportedException('Algorithm not supported.');
    }

    /**
     * Verifies the message with the given signature, key, and algorithm.
     * Not all methods are symmetric, so we must have a separate verify and sign method.
     *
     * @param string $key
     * @param string $signature
     * @param string $message
     *
     * @return bool
     * @throws JwtExceptionInterface
     * @author Bas Milius <bas@mili.us>
     * @since 2.0.0
     */
    public function verify(string $key, string $signature, string $message): bool
    {
        $algorithm = match ($this) {
            self::HS256, self::RS256 => 'sha256',
            self::HS384, self::RS384 => 'sha384',
            self::HS512, self::RS512 => 'sha512'
        };

        switch ($this) {
            case self::HS256:
            case self::HS384:
            case self::HS512:
                return hash_equals($signature, hash_hmac($algorithm, $message, $key, binary: true));

            case self::RS256:
            case self::RS384:
            case self::RS512:
                $result = openssl_verify($message, $signature, $key, $algorithm);

                if ($result === -1) {
                    throw new JwtEncryptionException(openssl_error_string() ?: 'Unknown OpenSSL error.');
                }

                return $result === 1;
        }

        throw new JwtUnsupportedException('Algorithm not supported.');
    }

}
