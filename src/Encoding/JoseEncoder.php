<?php

declare (strict_types=1);
namespace Lcobucci\JWT\Encoding;

use function json_decode;
use function json_encode;
use const JSON_THROW_ON_ERROR;
use const JSON_UNESCAPED_SLASHES;
use const JSON_UNESCAPED_UNICODE;
use Json_Exception;
use Lcobucci\JWT\Decoder;
use Lcobucci\JWT\Encoder;
use Lcobucci\JWT\Sodium_Base64polyfill;
/**
 * A utilitarian class that encodes and decodes data according to JOSE specifications
 */
final readonly class Jose_Encoder implements Encoder, Decoder
{
    public function json_encode(mixed $data): string
    {
        try {
            return json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
        } catch (Json_Exception $exception) {
            throw Cannot_Encode_Content::json_issues($exception);
        }
    }
    public function json_decode(string $json): mixed
    {
        try {
            return json_decode(json: $json, associative: true, flags: JSON_THROW_ON_ERROR);
        } catch (Json_Exception $exception) {
            throw Cannot_Decode_Content::json_issues($exception);
        }
    }
    public function base64url_encode(string $data): string
    {
        return Sodium_Base64polyfill::bin2base64($data, Sodium_Base64polyfill::SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
    }
    public function base64url_decode(string $data): string
    {
        return Sodium_Base64polyfill::base642bin($data, Sodium_Base64polyfill::SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
    }
}