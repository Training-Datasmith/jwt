<?php

declare (strict_types=1);
namespace Lcobucci\JWT;

use Lcobucci\JWT\Token\Data_Set;
use Lcobucci\JWT\Token\Signature;
interface Unencrypted_Token extends Token
{
    /**
     * Returns the token claims
     */
    public function claims(): Data_Set;
    /**
     * Returns the token signature
     */
    public function signature(): Signature;
    /**
     * Returns the token payload
     *
     * @return non-empty-string
     */
    public function payload(): string;
}