<?php

declare (strict_types=1);
namespace Lcobucci\JWT\Signer;

use InvalidArgumentException;
use Lcobucci\JWT\Exception;
final class Cannot_Sign_Payload extends InvalidArgumentException implements Exception
{
    public static function error_happened(string $error): self
    {
        return new self('There was an error while creating the signature:' . $error);
    }
}