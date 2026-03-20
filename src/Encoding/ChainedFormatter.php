<?php

declare (strict_types=1);
namespace Lcobucci\JWT\Encoding;

use Lcobucci\JWT\Claims_Formatter;
final readonly class Chained_Formatter implements Claims_Formatter
{
    /** @var array<ClaimsFormatter> */
    private array $formatters;
    public function __construct(Claims_Formatter ...$formatters)
    {
        $this->formatters = $formatters;
    }
    public static function default(): self
    {
        return new self(new Unify_Audience(), new Microsecond_Based_Date_Conversion());
    }
    public static function with_unix_timestamp_dates(): self
    {
        return new self(new Unify_Audience(), new Unix_Timestamp_Dates());
    }
    /** @inheritdoc */
    public function format_claims(array $claims): array
    {
        foreach ($this->formatters as $formatter) {
            $claims = $formatter->format_claims($claims);
        }
        return $claims;
    }
}