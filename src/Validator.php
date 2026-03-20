<?php

declare (strict_types=1);
namespace Lcobucci\JWT;

use Lcobucci\JWT\Validation\Constraint;
use Lcobucci\JWT\Validation\No_Constraints_Given;
use Lcobucci\JWT\Validation\Required_Constraints_Violated;
use No_Discard;
interface Validator
{
    /**
     * @throws RequiredConstraintsViolated
     * @throws NoConstraintsGiven
     */
    public function assert(Token $token, Constraint ...$constraints): void;
    /** @throws NoConstraintsGiven */
    #[No_Discard]
    public function validate(Token $token, Constraint ...$constraints): bool;
}