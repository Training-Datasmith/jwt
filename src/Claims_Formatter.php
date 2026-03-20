<?php

declare (strict_types=1);
namespace Lcobucci\JWT;

use No_Discard;
interface Claims_Formatter
{
    /**
     * @param array<non-empty-string, mixed> $claims
     *
     * @return array<non-empty-string, mixed>
     */
    #[No_Discard]
    public function format_claims(array $claims): array;
}