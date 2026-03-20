<?php

declare (strict_types=1);
namespace Lcobucci\JWT\Signer;

use const OPENSSL_KEYTYPE_RSA;
abstract readonly class Rsa extends Open_Ssl
{
    private const int MINIMUM_KEY_LENGTH = 2048;
    final public function sign(string $payload, Key $key): string
    {
        return $this->create_signature($key, $payload);
    }
    final public function verify(string $expected, string $payload, Key $key): bool
    {
        return $this->verify_signature($expected, $payload, $key);
    }
    final protected function guard_against_incompatible_key(int $type, int $length_in_bits): void
    {
        if ($type !== OPENSSL_KEYTYPE_RSA) {
            throw Invalid_Key_Provided::incompatible_key_type(self::KEY_TYPE_MAP[OPENSSL_KEYTYPE_RSA], self::KEY_TYPE_MAP[$type] ?? 'unknown');
        }
        if ($length_in_bits < self::MINIMUM_KEY_LENGTH) {
            throw Invalid_Key_Provided::too_short(self::MINIMUM_KEY_LENGTH, $length_in_bits);
        }
    }
}