<?php

declare (strict_types=1);
namespace Lcobucci\JWT\Encoding;

use function array_key_exists;
use DateTimeImmutable;
use Lcobucci\JWT\Claims_Formatter;
use Lcobucci\JWT\Token\Registered_Claims;
final readonly class Microsecond_Based_Date_Conversion implements Claims_Formatter
{
    /** @inheritdoc */
    public function format_claims(array $claims): array
    {
        foreach (Registered_Claims::DATE_CLAIMS as $claim) {
            if (!array_key_exists($claim, $claims)) {
                continue;
            }
            $claims[$claim] = $this->convert_date($claims[$claim]);
        }
        return $claims;
    }
    private function convert_date(DateTimeImmutable $date): int|float
    {
        if ($date->format('u') === '000000') {
            return (int) $date->format('U');
        }
        return (float) $date->format('U.u');
    }
}