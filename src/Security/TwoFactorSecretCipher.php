<?php

declare(strict_types=1);

namespace Tavy315\SyliusTwoFactorPlugin\Security;

final class TwoFactorSecretCipher
{
    public static function encrypt(string $secret): string
    {
        $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);

        return base64_encode($nonce . sodium_crypto_secretbox($secret, $nonce, self::key()));
    }

    public static function decrypt(string $encryptedSecret): string
    {
        $payload = base64_decode($encryptedSecret, true);
        if ($payload === false || strlen($payload) <= SODIUM_CRYPTO_SECRETBOX_NONCEBYTES) {
            throw new \RuntimeException('The stored two-factor secret is invalid.');
        }

        $secret = sodium_crypto_secretbox_open(
            substr($payload, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES),
            substr($payload, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES),
            self::key(),
        );

        if ($secret === false) {
            throw new \RuntimeException('The stored two-factor secret cannot be decrypted.');
        }

        return $secret;
    }

    private static function key(): string
    {
        $key = base64_decode((string) ($_SERVER['TWO_FACTOR_ENCRYPTION_KEY'] ?? $_ENV['TWO_FACTOR_ENCRYPTION_KEY'] ?? ''), true);
        if ($key === false || strlen($key) !== SODIUM_CRYPTO_SECRETBOX_KEYBYTES) {
            throw new \RuntimeException('TWO_FACTOR_ENCRYPTION_KEY must be a base64-encoded 32-byte key.');
        }

        return $key;
    }
}
