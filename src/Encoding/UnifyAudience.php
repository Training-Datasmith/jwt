<?php

declare (strict_types=1);
namespace Lcobucci\JWT\Encoding;

use function array_key_exists;
use function count;
use function current;
use Lcobucci\JWT\Claims_Formatter;
use Lcobucci\JWT\Token\Registered_Claims;
final readonly class Unify_Audience implements Claims_Formatter
{
    /** @inheritdoc */
    public function format_claims(array $claims): array
    {
        if (!array_key_exists(Registered_Claims::AUDIENCE, $claims) || count($claims[Registered_Claims::AUDIENCE]) !== 1) {
            return $claims;
        }
        $claims[Registered_Claims::AUDIENCE] = current($claims[Registered_Claims::AUDIENCE]);
        return $claims;
    }
}