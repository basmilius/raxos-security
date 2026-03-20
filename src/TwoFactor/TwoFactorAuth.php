<?php
declare(strict_types=1);

namespace Raxos\Security\TwoFactor;

use Random\RandomException;
use Raxos\Contract\Security\TwoFactorAuthExceptionInterface;
use Raxos\Error\InvalidArgumentException;
use Raxos\Security\Error\TwoFactorAuthInvalidDataException;
use Raxos\Security\Error\TwoFactorAuthRandomizerException;
use function array_search;
use function bindec;
use function ceil;
use function chr;
use function chunk_split;
use function decbin;
use function explode;
use function floor;
use function hash_equals;
use function hash_hmac;
use function implode;
use function ord;
use function pack;
use function preg_match;
use function preg_quote;
use function random_bytes;
use function rawurlencode;
use function str_pad;
use function str_split;
use function strlen;
use function strtoupper;
use function substr;
use function time;
use function trim;
use function unpack;
use function vsprintf;
use const STR_PAD_LEFT;

/**
 * Class TwoFactorAuth
 *
 * @author Bas Milius <bas@mili.us>
 * @package Raxos\Security\TwoFactor
 * @since 2.0.0
 */
readonly class TwoFactorAuth
{

    public const array BASE32 = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '2', '3', '4', '5', '6', '7', '='];

    /**
     * TwoFactorAuth constructor.
     *
     * @param string|null $issuer
     * @param int $digits
     * @param int $period
     * @param TwoFactorAuthAlgorithm $algorithm
     *
     * @throws InvalidArgumentException
     * @author Bas Milius <bas@mili.us>
     * @since 2.0.0
     */
    public function __construct(
        public ?string $issuer = null,
        public int $digits = 6,
        public int $period = 30,
        public TwoFactorAuthAlgorithm $algorithm = TwoFactorAuthAlgorithm::SHA1
    )
    {
        if ($this->digits <= 0) {
            throw new InvalidArgumentException('The amount of digits must be a positive integer.');
        }

        if ($this->period <= 0) {
            throw new InvalidArgumentException('The period must be a positive integer.');
        }
    }

    /**
     * Generates a new secret with the given number of bits.
     *
     * @param int $bits
     *
     * @return string
     * @throws TwoFactorAuthExceptionInterface
     * @author Bas Milius <bas@mili.us>
     * @since 2.0.0
     */
    public function createSecret(int $bits = 160): string
    {
        try {
            $bytes = (int)ceil($bits / 5);
            $random = random_bytes($bytes);
            $secret = '';

            for ($i = 0; $i < $bytes; $i++) {
                $secret .= self::BASE32[ord($random[$i]) & 31];
            }

            return $secret;
        } catch (RandomException $err) {
            throw new TwoFactorAuthRandomizerException($err);
        }
    }

    /**
     * Generates a code for the given secret.
     *
     * @param string $secret
     * @param int|null $time
     *
     * @return string
     * @throws TwoFactorAuthExceptionInterface
     * @author Bas Milius <bas@mili.us>
     * @since 2.0.0
     */
    public function generateCode(string $secret, ?int $time = null): string
    {
        $time ??= time();

        $secretKey = $this->base32Decode($secret);
        $timestamp = "\0\0\0\0" . pack('N*', $this->getTimeSlice($time));
        $hashHmac = hash_hmac($this->algorithm->value, $timestamp, $secretKey, true);
        $hashPart = substr($hashHmac, ord(substr($hashHmac, -1)) & 0x0F, 4);
        $value = unpack('N', $hashPart);
        $value = $value[1] & 0x7FFFFFFF;

        return str_pad((string)($value % (10 ** $this->digits)), $this->digits, '0', STR_PAD_LEFT);
    }

    /**
     * Generates the otpauth:// url for authenticator apps.
     *
     * @param string $secret
     * @param string $label
     *
     * @return string
     * @author Bas Milius <bas@mili.us>
     * @since 2.0.0
     */
    public function generateQrData(string $secret, string $label): string
    {
        $params = [
            rawurlencode($label),
            rawurlencode($secret),
            $this->period,
            rawurlencode(strtoupper($this->algorithm->value)),
            $this->digits
        ];

        if ($this->issuer !== null) {
            return vsprintf('otpauth://totp/%s?secret=%s&issuer=%s&period=%d&algorithm=%s&digits=%d', [
                $params[0],
                $params[1],
                rawurlencode($this->issuer),
                $params[2],
                $params[3],
                $params[4]
            ]);
        }

        return vsprintf('otpauth://totp/%s?secret=%s&period=%d&algorithm=%s&digits=%d', $params);
    }

    /**
     * Verifies the given code.
     *
     * @param string $secret
     * @param string $code
     * @param int $discrepancy
     *
     * @return bool
     * @throws TwoFactorAuthExceptionInterface
     * @author Bas Milius <bas@mili.us>
     * @since 2.0.0
     */
    public function verifyCode(string $secret, string $code, int $discrepancy = 1): bool
    {
        $timestamp = time();

        for ($i = -$discrepancy; $i <= $discrepancy; $i++) {
            $ts = $timestamp + $i * $this->period;

            if (hash_equals($this->generateCode($secret, $ts), $code)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Decodes the provided base32 encoded string.
     *
     * @param string $value
     *
     * @return string
     * @throws TwoFactorAuthExceptionInterface
     * @author Bas Milius <bas@mili.us>
     * @since 2.0.0
     */
    private function base32Decode(string $value): string
    {
        if (empty($value)) {
            return '';
        }

        if (preg_match('/[^' . preg_quote(implode('', self::BASE32)) . ']/', $value) !== 0) {
            throw new TwoFactorAuthInvalidDataException('The given value is an invalid base32 string.');
        }

        $buffer = '';

        foreach (str_split($value) as $character) {
            if ($character !== '=') {
                $buffer .= str_pad(decbin(array_search($character, self::BASE32, true)), 5, '0', STR_PAD_LEFT);
            }
        }

        $length = strlen($buffer);
        $blocks = trim(chunk_split(substr($buffer, 0, $length - ($length % 8)), 8, ' '));
        $output = '';

        foreach (explode(' ', $blocks) as $block) {
            $output .= chr(bindec(str_pad($block, 8, '0')));
        }

        return $output;
    }

    /**
     * Gets the time slice with an optional offset.
     *
     * @param int $time
     *
     * @return int
     * @author Bas Milius <bas@mili.us>
     * @since 2.0.0
     */
    private function getTimeSlice(int $time = 0): int
    {
        return (int)floor($time / $this->period);
    }

}
