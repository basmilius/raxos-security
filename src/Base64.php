<?php
declare(strict_types=1);

namespace Raxos\Security;

use JetBrains\PhpStorm\Pure;
use function array_map;
use function base64_decode;
use function base64_encode;
use function chr;
use function implode;
use function ord;
use function str_split;
use function strtr;

/**
 * Class Base64
 *
 * @author Bas Milius <bas@mili.us>
 * @package Raxos\Security
 * @since 2.0.0
 */
final class Base64
{

    /**
     * Decodes the given base64 string.
     *
     * @param string $data
     *
     * @return string
     * @author Bas Milius <bas@mili.us>
     * @since 2.0.0
     */
    #[Pure]
    public static function decode(string $data): string
    {
        return base64_decode($data);
    }

    /**
     * Encodes the given string to base64.
     *
     * @param string $data
     *
     * @return string
     * @author Bas Milius <bas@mili.us>
     * @since 2.0.0
     */
    #[Pure]
    public static function encode(string $data): string
    {
        return base64_encode($data);
    }

    /**
     * Decodes shuffled base64.
     *
     * @param string $data
     * @param int $amount
     *
     * @return string
     * @author Bas Milius <bas@mili.us>
     * @since 2.0.0
     */
    public static function decodeShuffle(string $data, int $amount = 1): string
    {
        $parts = str_split($data);
        $parts = array_map(static fn(string $char) => chr(ord($char) - $amount), $parts);
        $data = implode('', $parts);

        return self::decode($data);
    }

    /**
     * Encodes to shuffled base64.
     *
     * @param string $data
     * @param int $amount
     *
     * @return string
     * @author Bas Milius <bas@mili.us>
     * @since 2.0.0
     */
    public static function encodeShuffle(string $data, int $amount = 1): string
    {
        $data = self::encode($data);
        $parts = str_split($data);
        $data = array_map(static fn(string $char) => chr(ord($char) + $amount), $parts);

        return implode('', $data);
    }

    /**
     * Decodes the given url-safe base64 string.
     *
     * @param string $data
     *
     * @return string
     * @author Bas Milius <bas@mili.us>
     * @since 2.0.0
     */
    #[Pure]
    public static function decodeUrlSafe(string $data): string
    {
        return self::decode(strtr($data, [
            '-' => '+',
            '_' => '/'
        ]));
    }

    /**
     * Encodes the given string to url-safe base64.
     *
     * @param string $data
     *
     * @return string
     * @author Bas Milius <bas@mili.us>
     * @since 2.0.0
     */
    #[Pure]
    public static function encodeUrlSafe(string $data): string
    {
        return strtr(self::encode($data), [
            '+' => '-',
            '/' => '_',
            '=' => ''
        ]);
    }

}
