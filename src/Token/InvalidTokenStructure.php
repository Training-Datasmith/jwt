<?php

declare (strict_types=1);
namespace Lcobucci\JWT\Token;

use InvalidArgumentException;
use Lcobucci\JWT\Exception;
final class Invalid_Token_Structure extends InvalidArgumentException implements Exception
{
    public static function missing_or_not_enough_separators(): self
    {
        return new self('The JWT string must have two dots');
    }
    public static function missing_header_part(): self
    {
        return new self('The JWT string is missing the Header part');
    }
    public static function missing_claims_part(): self
    {
        return new self('The JWT string is missing the Claim part');
    }
    public static function missing_signature_part(): self
    {
        return new self('The JWT string is missing the Signature part');
    }
    /** @param non-empty-string $part */
    public static function array_expected(string $part): self
    {
        return new self($part . ' must be an array with non-empty-string keys');
    }
    public static function date_is_not_parseable(string $value): self
    {
        return new self('Value is not in the allowed date format: ' . $value);
    }
}