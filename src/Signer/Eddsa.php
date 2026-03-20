<?php

declare (strict_types=1);
namespace Lcobucci\JWT\Signer;

use Lcobucci\JWT\Signer;
use function sodium_crypto_sign_detached;
use function sodium_crypto_sign_verify_detached;
use Sodium_Exception;
final readonly class Eddsa implements Signer
{
    public function algorithm_id(): string
    {
        return 'EdDSA';
    }
    public function sign(string $payload, Key $key): string
    {
        try {
            return sodium_crypto_sign_detached($payload, $key->contents());
        } catch (Sodium_Exception $sodium_exception) {
            throw new Invalid_Key_Provided($sodium_exception->get_message(), 0, $sodium_exception);
        }
    }
    public function verify(string $expected, string $payload, Key $key): bool
    {
        try {
            return sodium_crypto_sign_verify_detached($expected, $payload, $key->contents());
        } catch (Sodium_Exception $sodium_exception) {
            throw new Invalid_Key_Provided($sodium_exception->get_message(), 0, $sodium_exception);
        }
    }
}