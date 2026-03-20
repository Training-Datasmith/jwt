<?php

declare (strict_types=1);
namespace Lcobucci\JWT\Signer;

use InvalidArgumentException;
use Lcobucci\JWT\Exception;
final class Invalid_Key_Provided extends InvalidArgumentException implements Exception
{
    public static function cannot_be_parsed(string $details): self
    {
        return new self('It was not possible to parse your key, reason:' . $details);
    }
    /**
     * @param non-empty-string $expectedType
     * @param non-empty-string $actualType
     */
    public static function incompatible_key_type(string $expected_type, string $actual_type): self
    {
        return new self('The type of the provided key is not "' . $expected_type . '", "' . $actual_type . '" provided');
    }
    /** @param positive-int $expectedLength */
    public static function incompatible_key_length(int $expected_length, int $actual_length): self
    {
        return new self('The length of the provided key is different than ' . $expected_length . ' bits, ' . $actual_length . ' bits provided');
    }
    public static function cannot_be_empty(): self
    {
        return new self('Key cannot be empty');
    }
    public static function too_short(int $expected_length, int $actual_length): self
    {
        return new self('Key provided is shorter than ' . $expected_length . ' bits,' . ' only ' . $actual_length . ' bits provided');
    }
}