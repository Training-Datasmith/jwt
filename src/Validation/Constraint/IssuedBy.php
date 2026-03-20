<?php

declare (strict_types=1);
namespace Lcobucci\JWT\Validation\Constraint;

use Lcobucci\JWT\Token;
use Lcobucci\JWT\Validation\Constraint;
use Lcobucci\JWT\Validation\Constraint_Violation;
final readonly class Issued_By implements Constraint
{
    /** @var non-empty-string[] */
    private array $issuers;
    /** @param non-empty-string ...$issuers */
    public function __construct(string ...$issuers)
    {
        $this->issuers = $issuers;
    }
    public function assert(Token $token): void
    {
        if (!$token->has_been_issued_by(...$this->issuers)) {
            throw Constraint_Violation::error('The token was not issued by the given issuers', $this);
        }
    }
}