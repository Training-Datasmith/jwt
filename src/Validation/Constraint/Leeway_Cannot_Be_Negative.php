<?php

declare (strict_types=1);
namespace Lcobucci\JWT\Validation\Constraint;

use InvalidArgumentException;
use Lcobucci\JWT\Exception;
final class Leeway_Cannot_Be_Negative extends InvalidArgumentException implements Exception
{
    public static function create(): self
    {
        return new self('Leeway cannot be negative');
    }
}