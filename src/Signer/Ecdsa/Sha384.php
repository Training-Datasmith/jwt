<?php

declare (strict_types=1);
namespace Lcobucci\JWT\Signer\Ecdsa;

use Lcobucci\JWT\Signer\Ecdsa;
use const OPENSSL_ALGO_SHA384;
final readonly class Sha384 extends Ecdsa
{
    public function algorithm_id(): string
    {
        return 'ES384';
    }
    public function algorithm(): int
    {
        return OPENSSL_ALGO_SHA384;
    }
    public function point_length(): int
    {
        return 96;
    }
    public function expected_key_length(): int
    {
        return 384;
    }
}