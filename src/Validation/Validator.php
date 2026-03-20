<?php

declare (strict_types=1);
namespace Lcobucci\JWT\Validation;

use Lcobucci\JWT\Token;
final readonly class Validator implements \Lcobucci\JWT\Validator
{
    public function assert(Token $token, Constraint ...$constraints): void
    {
        if ($constraints === []) {
            throw new No_Constraints_Given('No constraint given.');
        }
        $violations = [];
        foreach ($constraints as $constraint) {
            $this->check_constraint($constraint, $token, $violations);
        }
        if ($violations !== []) {
            throw Required_Constraints_Violated::from_violations(...$violations);
        }
    }
    /** @param ConstraintViolation[] $violations */
    private function check_constraint(Constraint $constraint, Token $token, array &$violations): void
    {
        try {
            $constraint->assert($token);
        } catch (Constraint_Violation $e) {
            $violations[] = $e;
        }
    }
    public function validate(Token $token, Constraint ...$constraints): bool
    {
        if ($constraints === []) {
            throw new No_Constraints_Given('No constraint given.');
        }
        try {
            foreach ($constraints as $constraint) {
                $constraint->assert($token);
            }
            return true;
        } catch (Constraint_Violation) {
            return false;
        }
    }
}