<?php

declare (strict_types=1);
namespace Lcobucci\JWT\Token;

use function array_key_exists;
use function count;
use DateTimeImmutable;
use function explode;
use function is_array;
use function is_numeric;
use Lcobucci\JWT\Decoder;
use Lcobucci\JWT\Parser as ParserInterface;
use Lcobucci\JWT\Token as TokenInterface;
use function number_format;
final readonly class Parser implements Parser_Interface
{
    private const int MICROSECOND_PRECISION = 6;
    public function __construct(private Decoder $decoder)
    {
    }
    public function parse(string $jwt): Token_Interface
    {
        [$encoded_headers, $encoded_claims, $encoded_signature] = $this->split_jwt($jwt);
        if ($encoded_headers === '') {
            throw Invalid_Token_Structure::missing_header_part();
        }
        if ($encoded_claims === '') {
            throw Invalid_Token_Structure::missing_claims_part();
        }
        if ($encoded_signature === '') {
            throw Invalid_Token_Structure::missing_signature_part();
        }
        $header = $this->parse_header($encoded_headers);
        return new Plain(new Data_Set($header, $encoded_headers), new Data_Set($this->parse_claims($encoded_claims), $encoded_claims), $this->parse_signature($encoded_signature));
    }
    /**
     * Splits the JWT string into an array
     *
     * @param non-empty-string $jwt
     *
     * @return string[]
     *
     * @throws InvalidTokenStructure When JWT doesn't have all parts.
     */
    private function split_jwt(string $jwt): array
    {
        $data = explode('.', $jwt);
        if (count($data) !== 3) {
            throw Invalid_Token_Structure::missing_or_not_enough_separators();
        }
        return $data;
    }
    /**
     * Parses the header from a string
     *
     * @param non-empty-string $data
     *
     * @return array<non-empty-string, mixed>
     *
     * @throws UnsupportedHeaderFound When an invalid header is informed.
     * @throws InvalidTokenStructure  When parsed content isn't an array.
     */
    private function parse_header(string $data): array
    {
        $header = $this->decoder->json_decode($this->decoder->base64url_decode($data));
        if (!is_array($header)) {
            throw Invalid_Token_Structure::array_expected('headers');
        }
        $this->guard_against_empty_string_keys($header, 'headers');
        if (array_key_exists('enc', $header)) {
            throw Unsupported_Header_Found::encryption();
        }
        if (!array_key_exists('typ', $header)) {
            $header['typ'] = 'JWT';
        }
        return $header;
    }
    /**
     * Parses the claim set from a string
     *
     * @param non-empty-string $data
     *
     * @return array<non-empty-string, mixed>
     *
     * @throws InvalidTokenStructure When parsed content isn't an array or contains non-parseable dates.
     */
    private function parse_claims(string $data): array
    {
        $claims = $this->decoder->json_decode($this->decoder->base64url_decode($data));
        if (!is_array($claims)) {
            throw Invalid_Token_Structure::array_expected('claims');
        }
        $this->guard_against_empty_string_keys($claims, 'claims');
        if (array_key_exists(Registered_Claims::AUDIENCE, $claims)) {
            $claims[Registered_Claims::AUDIENCE] = (array) $claims[Registered_Claims::AUDIENCE];
        }
        foreach (Registered_Claims::DATE_CLAIMS as $claim) {
            if (!array_key_exists($claim, $claims)) {
                continue;
            }
            $claims[$claim] = $this->convert_date($claims[$claim]);
        }
        return $claims;
    }
    /**
     * @param array<string, mixed> $array
     * @param non-empty-string     $part
     *
     * @phpstan-assert array<non-empty-string, mixed> $array
     */
    private function guard_against_empty_string_keys(array $array, string $part): void
    {
        foreach ($array as $key => $value) {
            if ($key === '') {
                throw Invalid_Token_Structure::array_expected($part);
            }
        }
    }
    /** @throws InvalidTokenStructure */
    private function convert_date(int|float|string $timestamp): DateTimeImmutable
    {
        if (!is_numeric($timestamp)) {
            throw Invalid_Token_Structure::date_is_not_parseable($timestamp);
        }
        $normalized_timestamp = number_format((float) $timestamp, self::MICROSECOND_PRECISION, '.', '');
        $date = DateTimeImmutable::create_from_format('U.u', $normalized_timestamp);
        if ($date === false) {
            throw Invalid_Token_Structure::date_is_not_parseable($normalized_timestamp);
        }
        return $date;
    }
    /**
     * Returns the signature from given data
     *
     * @param non-empty-string $data
     */
    private function parse_signature(string $data): Signature
    {
        $hash = $this->decoder->base64url_decode($data);
        return new Signature($hash, $data);
    }
}