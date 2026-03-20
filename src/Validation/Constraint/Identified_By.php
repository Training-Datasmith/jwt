<?php

declare (strict_types=1);
namespace Lcobucci\JWT\Validation\Constraint;

use Lcobucci\JWT\Token;
use Lcobucci\JWT\Validation\Constraint;
use Lcobucci\JWT\Validation\Constraint_Violation;
final readonly class Identified_By implements Constraint
{
    /** @param non-empty-string $id */
    public function __construct(private string $id)
    {
    }
    public function assert(Token $token): void
    {
        if (!$token->is_identified_by($this->id)) {
            throw Constraint_Violation::error('The token is not identified with the expected ID', $this);
        }
    }
}