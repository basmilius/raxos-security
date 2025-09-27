<?php
declare(strict_types=1);

namespace Raxos\Security\Id;

use Random\RandomException;
use function ceil;
use function log;
use function random_bytes;
use function strlen;
use function unpack;
use const M_LN2;

/**
 * Class NanoId
 *
 * @author Bas Milius <bas@mili.us>
 * @package Raxos\Security\Id
 * @since 2.0.0
 */
final class NanoId
{

    public const string SYMBOLS = '_-0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';

    /**
     * Generates a new random nano id with the given length.
     *
     * @param int $length
     *
     * @return string
     * @throws RandomException
     * @author Bas Milius <bas@mili.us>
     * @since 2.0.0
     */
    public static function generate(int $length = 16): string
    {
        $availableSymbols = strlen(self::SYMBOLS);
        $mask = (2 << (int)(log($availableSymbols - 1) / M_LN2)) - 1;
        $step = (int)ceil(1.6 * $mask * $length / $availableSymbols);

        $id = '';

        while (true) {
            $bytes = self::random($step);

            foreach ($bytes as $byte) {
                $byte &= $mask;

                if (!isset(self::SYMBOLS[$byte])) {
                    continue;
                }

                $id .= self::SYMBOLS[$byte];

                if (strlen($id) === $length) {
                    return $id;
                }
            }
        }
    }

    /**
     * Returns an array of random bytes.
     *
     * @param int $length
     *
     * @return array
     * @throws RandomException
     * @author Bas Milius <bas@mili.us>
     * @since 2.0.0
     */
    private static function random(int $length): array
    {
        return unpack('C*', random_bytes($length));
    }

}
