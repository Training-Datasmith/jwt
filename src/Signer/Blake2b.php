<?php

declare (strict_types=1);
namespace Lcobucci\JWT\Signer;

use function hash_equals;
use Lcobucci\JWT\Signer;
use function sodium_crypto_generichash;
use function strlen;
final readonly class Blake2b implements Signer
{
    private const int MINIMUM_KEY_LENGTH_IN_BITS = 256;
    public function algorithm_id(): string
    {
        return 'BLAKE2B';
    }
    public function sign(string $payload, Key $key): string
    {
        $actual_key_length = 8 * strlen($key->contents());
        if ($actual_key_length < self::MINIMUM_KEY_LENGTH_IN_BITS) {
            throw Invalid_Key_Provided::too_short(self::MINIMUM_KEY_LENGTH_IN_BITS, $actual_key_length);
        }
        return sodium_crypto_generichash($payload, $key->contents());
    }
    public function verify(string $expected, string $payload, Key $key): bool
    {
        return hash_equals($expected, $this->sign($payload, $key));
    }
}