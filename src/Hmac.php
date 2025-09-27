<?php
declare(strict_types=1);

namespace Raxos\Security;

use JetBrains\PhpStorm\ExpectedValues;
use function hash_hmac;

/**
 * Class Hmac
 *
 * @author Bas Milius <bas@mili.us>
 * @package Raxos\Security
 * @since 2.0.0
 */
final class Hmac
{

    private const array ALGOS = [
        'md2',
        'md4',
        'md5',
        'sha1',
        'sha224',
        'sha256',
        'sha384',
        'sha512/224',
        'sha512/256',
        'sha512',
        'sha3-224',
        'sha3-256',
        'sha3-384',
        'sha3-512',
        'ripemd128',
        'ripemd160',
        'ripemd256',
        'ripemd320',
        'whirlpool',
        'tiger128,3',
        'tiger160,3',
        'tiger192,3',
        'tiger128,4',
        'tiger160,4',
        'tiger192,4',
        'snefru',
        'snefru256',
        'gost',
        'gost-crypto',
        'haval128,3',
        'haval160,3',
        'haval192,3',
        'haval224,3',
        'haval256,3',
        'haval128,4',
        'haval160,4',
        'haval192,4',
        'haval224,4',
        'haval256,4',
        'haval128,5',
        'haval160,5',
        'haval192,5',
        'haval224,5',
        'haval256,5'
    ];

    /**
     * Returns the signature key for the given data.
     *
     * @param string $data
     * @param string $key
     * @param string $algo
     *
     * @return string
     * @author Bas Milius <bas@mili.us>
     * @since 2.0.0
     */
    public static function get(
        string $data,
        string $key,
        #[ExpectedValues(values: self::ALGOS)]
        string $algo = 'sha256'
    ): string
    {
        return Base64::encodeUrlSafe(hash_hmac($algo, $data, $key, true));
    }

    /**
     * Returns TRUE if the generated signature matches the actual value.
     *
     * @param string $actual
     * @param string $data
     * @param string $key
     *
     * @return bool
     * @author Bas Milius <bas@mili.us>
     * @since 2.0.0
     */
    public static function matches(string $actual, string $data, string $key): bool
    {
        return $actual === self::get($data, $key);
    }

}
