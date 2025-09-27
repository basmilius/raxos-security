<?php
declare(strict_types=1);

namespace Raxos\Foundation\Security\TwoFactor;

/**
 * Enum TwoFactorAuthAlgorithm
 *
 * @author Bas Milius <bas@mili.us>
 * @package Raxos\Foundation\Security\TwoFactor
 * @since 1.0.17
 */
enum TwoFactorAuthAlgorithm: string
{
    case SHA1 = 'sha1';
    case SHA256 = 'sha256';
    case SHA512 = 'sha512';
    case MD5 = 'md5';
}
