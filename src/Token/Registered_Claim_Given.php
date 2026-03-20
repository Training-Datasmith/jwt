<?php

declare (strict_types=1);
namespace Lcobucci\JWT\Token;

use InvalidArgumentException;
use Lcobucci\JWT\Exception;
use function sprintf;
final class Registered_Claim_Given extends InvalidArgumentException implements Exception
{
    private const DEFAULT_MESSAGE = 'Builder#withClaim() is meant to be used for non-registered claims, ' . 'check the documentation on how to set claim "%s"';
    /** @param non-empty-string $name */
    public static function for_claim(string $name): self
    {
        return new self(sprintf(self::DEFAULT_MESSAGE, $name));
    }
}