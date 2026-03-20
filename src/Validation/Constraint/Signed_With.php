<?php

declare (strict_types=1);
namespace Lcobucci\JWT\Validation\Constraint;

use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\Unencrypted_Token;
use Lcobucci\JWT\Validation\Constraint_Violation;
use Lcobucci\JWT\Validation\Signed_With as SignedWithInterface;
final readonly class Signed_With implements Signed_With_Interface
{
    public function __construct(private Signer $signer, private Signer\Key $key)
    {
    }
    public function assert(Token $token): void
    {
        if (!$token instanceof Unencrypted_Token) {
            throw Constraint_Violation::error('You should pass a plain token', $this);
        }
        if ($token->headers()->get('alg') !== $this->signer->algorithm_id()) {
            throw Constraint_Violation::error('Token signer mismatch', $this);
        }
        if (!$this->signer->verify($token->signature()->hash(), $token->payload(), $this->key)) {
            throw Constraint_Violation::error('Token signature mismatch', $this);
        }
    }
}