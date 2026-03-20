<?php

declare (strict_types=1);
namespace Lcobucci\JWT\Validation\Constraint;

use Lcobucci\JWT\Token;
use Lcobucci\JWT\Validation\Constraint_Violation;
use Lcobucci\JWT\Validation\Signed_With as SignedWithInterface;
final readonly class Signed_With_One_In_Set implements Signed_With_Interface
{
    /** @var array<SignedWithUntilDate> */
    private array $constraints;
    public function __construct(Signed_With_Until_Date ...$constraints)
    {
        $this->constraints = $constraints;
    }
    public function assert(Token $token): void
    {
        foreach ($this->constraints as $constraint) {
            try {
                $constraint->assert($token);
                return;
            } catch (Constraint_Violation) {
                // try next constraint
            }
        }
        throw Constraint_Violation::error('Token signature could not be verified against any known key', $this);
    }
}