<?php

declare (strict_types=1);
namespace Lcobucci\JWT\Signer\Key;

use InvalidArgumentException;
use Lcobucci\JWT\Exception;
use Throwable;
final class File_Could_Not_Be_Read extends InvalidArgumentException implements Exception
{
    /** @param non-empty-string $path */
    public static function on_path(string $path, ?Throwable $cause = null): self
    {
        return new self(message: 'The path "' . $path . '" does not contain a valid key file', previous: $cause);
    }
}