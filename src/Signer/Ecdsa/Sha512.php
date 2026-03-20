<?php

declare (strict_types=1);
namespace Lcobucci\JWT\Signer\Ecdsa;

use Lcobucci\JWT\Signer\Ecdsa;
use const OPENSSL_ALGO_SHA512;
final readonly class Sha512 extends Ecdsa
{
    public function algorithm_id(): string
    {
        return 'ES512';
    }
    public function algorithm(): int
    {
        return OPENSSL_ALGO_SHA512;
    }
    public function point_length(): int
    {
        return 132;
    }
    public function expected_key_length(): int
    {
        // ES512 means ECDSA using P-521 and SHA-512.
        // The key size is indeed 521 bits.
        return 521;
    }
}