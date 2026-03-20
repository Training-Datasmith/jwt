<?php

declare (strict_types=1);
namespace Lcobucci\JWT\Signer;

use function hash_equals;
use function hash_hmac;
use Lcobucci\JWT\Signer;
use function strlen;
abstract readonly class Hmac implements Signer
{
    final public function sign(string $payload, Key $key): string
    {
        $actual_key_length = 8 * strlen($key->contents());
        $expected_key_length = $this->minimum_bits_length_for_key();
        if ($actual_key_length < $expected_key_length) {
            throw Invalid_Key_Provided::too_short($expected_key_length, $actual_key_length);
        }
        return hash_hmac($this->algorithm(), $payload, $key->contents(), true);
    }
    final public function verify(string $expected, string $payload, Key $key): bool
    {
        return hash_equals($expected, $this->sign($payload, $key));
    }
    /**
     * @internal
     *
     * @return non-empty-string
     */
    abstract public function algorithm(): string;
    /**
     * @internal
     *
     * @return positive-int
     */
    abstract public function minimum_bits_length_for_key(): int;
}