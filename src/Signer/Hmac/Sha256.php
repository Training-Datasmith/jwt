<?php

declare (strict_types=1);
namespace Lcobucci\JWT\Signer\Hmac;

use Lcobucci\JWT\Signer\Hmac;
final readonly class Sha256 extends Hmac
{
    public function algorithm_id(): string
    {
        return 'HS256';
    }
    public function algorithm(): string
    {
        return 'sha256';
    }
    public function minimum_bits_length_for_key(): int
    {
        return 256;
    }
}