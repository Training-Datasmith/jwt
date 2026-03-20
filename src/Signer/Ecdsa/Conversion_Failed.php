<?php

declare (strict_types=1);
namespace Lcobucci\JWT\Signer\Ecdsa;

use InvalidArgumentException;
use Lcobucci\JWT\Exception;
final class Conversion_Failed extends InvalidArgumentException implements Exception
{
    public static function invalid_length(): self
    {
        return new self('Invalid signature length.');
    }
    public static function incorrect_start_sequence(): self
    {
        return new self('Invalid data. Should start with a sequence.');
    }
    public static function integer_expected(): self
    {
        return new self('Invalid data. Should contain an integer.');
    }
}