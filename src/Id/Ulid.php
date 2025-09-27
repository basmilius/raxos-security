<?php
declare(strict_types=1);

namespace Raxos\Security\Id;

use Random\RandomException;
use Raxos\Contract\Security\UlidExceptionInterface;
use Raxos\Security\Error\{UlidInvalidLengthException, UlidTimestampTooLargeException, UlidWrongCharactersException};
use Stringable;
use function microtime;
use function pow;
use function preg_match;
use function random_int;
use function sprintf;
use function str_split;
use function strlen;
use function strrev;
use function strripos;
use function strtolower;
use function strtoupper;
use function substr;

/**
 * Class Ulid
 *
 * @author Bas Milius <bas@mili.us>
 * @package Raxos\Security\Id
 * @since 2.0.0
 */
final class Ulid implements Stringable
{

    public const string ENCODING_CHARS = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
    public const int ENCODING_LENGTH = 32;
    public const int TIME_MAX = 281474976710655;
    public const int TIME_LENGTH = 10;
    public const int RANDOM_LENGTH = 16;

    private static int $lastGeneratedTime = 0;
    private static array $lastRandomChars = [];

    /**
     * Ulid constructor.
     *
     * @param string $time
     * @param string $randomness
     * @param bool $lowercase
     *
     * @author Bas Milius <bas@mili.us>
     * @since 2.0.0
     */
    public function __construct(
        public readonly string $time,
        public readonly string $randomness,
        public readonly bool $lowercase = false
    ) {}

    /**
     * Generates a new ulid from a string.
     *
     * @param string $value
     * @param bool $lowercase
     *
     * @return self
     * @throws UlidExceptionInterface
     * @author Bas Milius <bas@mili.us>
     * @since 2.0.0
     */
    public static function fromString(string $value, bool $lowercase = false): self
    {
        if (strlen($value) !== self::TIME_LENGTH + self::RANDOM_LENGTH) {
            throw new UlidInvalidLengthException($value);
        }

        $value = strtoupper($value);

        if (!preg_match(sprintf('!^[%s]{%d}$!', self::ENCODING_CHARS, self::TIME_LENGTH + self::RANDOM_LENGTH), $value)) {
            throw new UlidWrongCharactersException($value);
        }

        return new self(substr($value, 0, self::TIME_LENGTH), substr($value, self::TIME_LENGTH, self::RANDOM_LENGTH), $lowercase);
    }

    /**
     * Generates a new ulid from the given timestamp.
     *
     * @param int $milliseconds
     * @param bool $lowercase
     *
     * @return self
     * @throws RandomException
     * @author Bas Milius <bas@mili.us>
     * @since 2.0.0
     */
    public static function fromTimestamp(int $milliseconds, bool $lowercase = false): self
    {
        $duplicateTime = $milliseconds === self::$lastGeneratedTime;

        self::$lastGeneratedTime = $milliseconds;

        $timeChars = '';
        $randomChars = '';

        $encodingChars = self::ENCODING_CHARS;

        for ($i = self::TIME_LENGTH - 1; $i >= 0; $i--) {
            $mod = $milliseconds % self::ENCODING_LENGTH;
            $timeChars = $encodingChars[$mod] . $timeChars;
            $milliseconds = ($milliseconds - $mod) / self::ENCODING_LENGTH;
        }

        if (!$duplicateTime) {
            for ($i = 0; $i < self::RANDOM_LENGTH; $i++) {
                self::$lastRandomChars[$i] = random_int(0, 31);
            }
        } else {
            for ($i = self::RANDOM_LENGTH - 1; $i >= 0 && self::$lastRandomChars[$i] === 31; $i--) {
                self::$lastRandomChars[$i] = 0;
            }

            self::$lastRandomChars[$i]++;
        }

        for ($i = 0; $i < self::RANDOM_LENGTH; $i++) {
            $randomChars .= $encodingChars[self::$lastRandomChars[$i]];
        }

        return new self($timeChars, $randomChars, $lowercase);
    }

    /**
     * Generates a new ulid.
     *
     * @param bool $lowercase
     *
     * @return self
     * @throws RandomException
     * @author Bas Milius <bas@mili.us>
     * @since 2.0.0
     */
    public static function generate(bool $lowercase = false): self
    {
        $now = (int)(microtime(true) * 1000);

        return self::fromTimestamp($now, $lowercase);
    }

    /**
     * Converts the ulid to a timestamp.
     *
     * @return int
     * @throws UlidExceptionInterface
     * @author Bas Milius <bas@mili.us>
     * @since 2.0.0
     */
    public function toTimestamp(): int
    {
        $timeChars = str_split(strrev($this->time));
        $carry = 0;

        foreach ($timeChars as $index => $char) {
            if (($encodingIndex = strripos(self::ENCODING_CHARS, $char)) === false) {
                throw new UlidWrongCharactersException($char);
            }

            $carry += ($encodingIndex * pow(self::ENCODING_LENGTH, $index));
        }

        if ($carry > self::TIME_MAX) {
            throw new UlidTimestampTooLargeException();
        }

        return $carry;
    }

    /**
     * {@inheritdoc}
     * @author Bas Milius <bas@mili.us>
     * @since 2.0.0
     */
    public function __toString(): string
    {
        return ($value = $this->time . $this->randomness) && $this->lowercase ? strtolower($value) : strtoupper($value);
    }

}
