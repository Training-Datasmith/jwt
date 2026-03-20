<?php

declare (strict_types=1);
namespace Lcobucci\JWT\Validation\Constraint;

use Lcobucci\JWT\Token;
use Lcobucci\JWT\Validation\Constraint;
use Lcobucci\JWT\Validation\Constraint_Violation;
final readonly class Related_To implements Constraint
{
    /** @param non-empty-string $subject */
    public function __construct(private string $subject)
    {
    }
    public function assert(Token $token): void
    {
        if (!$token->is_related_to($this->subject)) {
            throw Constraint_Violation::error('The token is not related to the expected subject', $this);
        }
    }
}