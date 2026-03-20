<?php

declare (strict_types=1);
namespace Lcobucci\JWT\Encoding;

use Json_Exception;
use Lcobucci\JWT\Exception;
use RuntimeException;
final class Cannot_Decode_Content extends RuntimeException implements Exception
{
    public static function json_issues(Json_Exception $previous): self
    {
        return new self(message: 'Error while decoding from JSON', previous: $previous);
    }
    public static function invalid_base64string(): self
    {
        return new self('Error while decoding from Base64Url, invalid base64 characters detected');
    }
}