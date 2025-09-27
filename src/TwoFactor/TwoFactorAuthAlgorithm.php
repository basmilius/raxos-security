<?php
declare(strict_types=1);

namespace Raxos\Security\TwoFactor;

/**
 * Enum TwoFactorAuthAlgorithm
 *
 * @author Bas Milius <bas@mili.us>
 * @package Raxos\Security\TwoFactor
 * @since 2.0.0
 */
enum TwoFactorAuthAlgorithm: string
{
    case SHA1 = 'sha1';
    case SHA256 = 'sha256';
    case SHA512 = 'sha512';
    case MD5 = 'md5';
}
