<?php

declare (strict_types=1);
namespace Lcobucci\JWT\Validation\Constraint;

use Lcobucci\JWT\Token;
use Lcobucci\JWT\Validation\Constraint;
use Lcobucci\JWT\Validation\Constraint_Violation;
final readonly class Permitted_For implements Constraint
{
    /** @param non-empty-string $audience */
    public function __construct(private string $audience)
    {
    }
    public function assert(Token $token): void
    {
        if (!$token->is_permitted_for($this->audience)) {
            throw Constraint_Violation::error('The token is not allowed to be used by this audience', $this);
        }
    }
}