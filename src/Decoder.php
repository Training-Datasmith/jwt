<?php

declare (strict_types=1);
namespace Lcobucci\JWT;

use Lcobucci\JWT\Encoding\Cannot_Decode_Content;
use No_Discard;
interface Decoder
{
    /**
     * Decodes from JSON, validating the errors
     *
     * @param non-empty-string $json
     *
     * @throws CannotDecodeContent When something goes wrong while decoding.
     */
    #[No_Discard]
    public function json_decode(string $json): mixed;
    /**
     * Decodes from Base64URL
     *
     * @link http://tools.ietf.org/html/rfc4648#section-5
     *
     * @return ($data is non-empty-string ? non-empty-string : string)
     *
     * @throws CannotDecodeContent When something goes wrong while decoding.
     */
    #[No_Discard]
    public function base64url_decode(string $data): string;
}