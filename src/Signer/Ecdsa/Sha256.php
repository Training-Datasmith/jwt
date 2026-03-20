<?php

declare (strict_types=1);
namespace Lcobucci\JWT\Signer\Ecdsa;

use Lcobucci\JWT\Signer\Ecdsa;
use const OPENSSL_ALGO_SHA256;
final readonly class Sha256 extends Ecdsa
{
    public function algorithm_id(): string
    {
        return 'ES256';
    }
    public function algorithm(): int
    {
        return OPENSSL_ALGO_SHA256;
    }
    public function point_length(): int
    {
        return 64;
    }
    public function expected_key_length(): int
    {
        return 256;
    }
}