<?php

declare(strict_types=1);

namespace Lcobucci\JWT\Validation\Constraint;

use Lcobucci\JWT\Token;
use Lcobucci\JWT\Validation\ConstraintViolation;
use Lcobucci\JWT\Validation\SignedWith as SignedWithInterface;

final readonly class SignedWithOneInSet implements SignedWithInterface
{
    /** @var array<SignedWithUntilDate> */
    private array $constraints;

    public function __construct(SignedWithUntilDate ...$constraints)
    {
        $this->constraints = $constraints;
    }

    public function assert(Token $token): void
    {
        foreach ($this->constraints as $constraint) {
            try {
                $constraint->assert($token);

                return;
            } catch (ConstraintViolation) {
                // try next constraint
            }
        }

        throw ConstraintViolation::error(
            'Token signature could not be verified against any known key',
            $this,
        );
    }
}
