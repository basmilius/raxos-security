<a href="https://bas.dev">
    <img src="https://bmcdn.nl/assets/branding/logo.svg" alt="Bas Milius" height="48" />
</a>

---

# Raxos Security

JWT signing and verification, TOTP authentication, identifiers and token utilities.

[Documentation](https://raxos.dev/security/) | [Packagist](https://packagist.org/packages/raxos/security) | [Raxos](https://github.com/basmilius/raxos)

- JWT algorithms with an explicit verification policy.
- TOTP secrets, authenticator URLs and code verification.
- NanoID and ULID identifiers, HMAC and Base64 helpers.

## Installation

Requires PHP 8.5 or later. Enable the `openssl` PHP extension. Composer checks the remaining package and extension dependencies declared in [composer.json](composer.json).

```sh
composer require "raxos/security:^3.2"
```

## Usage

```php
<?php
declare(strict_types=1);

use Raxos\Security\Jwt\Jwt;
use Raxos\Security\Jwt\JwtAlgorithm;

require __DIR__ . '/vendor/autoload.php';

$key = random_bytes(32);
$token = Jwt::encode(['sub' => 'user-42', 'exp' => time() + 300], $key);
$payload = Jwt::decode($token, [$key], [JwtAlgorithm::HS256]);

echo $payload['sub'];
```

The example generates a temporary key. Applications should load their signing keys from configuration. Verification permits HS256 by default; pass the expected algorithms explicitly for other issuers. Multiple keys require a valid string `kid`. PEM keys are rejected as HMAC secrets.

## Documentation

- [JSON Web Tokens](https://raxos.dev/security/jwt)
- [Two factor authentication](https://raxos.dev/security/two-factor-auth)
- [Identifiers](https://raxos.dev/security/identifiers)
- [Encoding, signing and tokens](https://raxos.dev/security/utilities)

## Testing

Run this library's Pest suite from the Raxos workspace:

```sh
git clone --recurse-submodules https://github.com/basmilius/raxos.git
cd raxos
composer install
vendor/bin/pest --testsuite=security
```

See [Testing Raxos](https://github.com/basmilius/raxos/blob/main/TESTING.md) for PHP extensions, integration services and coverage commands. The library's [Tests workflow](.github/workflows/tests.yml) also runs in GitHub Actions.

## License

[MIT](LICENSE). Copyright (c) 2017 - present Bas Milius.
