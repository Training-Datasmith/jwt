<?php

declare (strict_types=1);
namespace Lcobucci\JWT;

use Lcobucci\JWT\Encoding\Cannot_Decode_Content;
use Lcobucci\JWT\Token\Invalid_Token_Structure;
use Lcobucci\JWT\Token\Unsupported_Header_Found;
use No_Discard;
interface Parser
{
    /**
     * Parses the JWT and returns a token
     *
     * @param non-empty-string $jwt
     *
     * @throws CannotDecodeContent      When something goes wrong while decoding.
     * @throws InvalidTokenStructure    When token string structure is invalid.
     * @throws UnsupportedHeaderFound   When parsed token has an unsupported header.
     */
    #[No_Discard]
    public function parse(string $jwt): Token;
}