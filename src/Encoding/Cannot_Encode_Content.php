<?php

declare (strict_types=1);
namespace Lcobucci\JWT\Encoding;

use Json_Exception;
use Lcobucci\JWT\Exception;
use RuntimeException;
final class Cannot_Encode_Content extends RuntimeException implements Exception
{
    public static function json_issues(Json_Exception $previous): self
    {
        return new self(message: 'Error while encoding to JSON', previous: $previous);
    }
}