<?php

declare (strict_types=1);
namespace Lcobucci\JWT;

use Lcobucci\JWT\Encoding\Cannot_Encode_Content;
use No_Discard;
interface Encoder
{
    /**
     * Encodes to JSON, validating the errors
     *
     * @return non-empty-string
     *
     * @throws CannotEncodeContent When something goes wrong while encoding.
     */
    #[No_Discard]
    public function json_encode(mixed $data): string;
    /**
     * Encodes to base64url
     *
     * @link http://tools.ietf.org/html/rfc4648#section-5
     *
     * @return ($data is non-empty-string ? non-empty-string : string)
     */
    #[No_Discard]
    public function base64url_encode(string $data): string;
}