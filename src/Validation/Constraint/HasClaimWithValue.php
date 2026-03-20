<?php

declare (strict_types=1);
namespace Lcobucci\JWT\Validation\Constraint;

use function in_array;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\Unencrypted_Token;
use Lcobucci\JWT\Validation\Constraint;
use Lcobucci\JWT\Validation\Constraint_Violation;
final readonly class Has_Claim_With_Value implements Constraint
{
    /** @param non-empty-string $claim */
    public function __construct(private string $claim, private mixed $expected_value)
    {
        if (in_array($claim, Token\Registered_Claims::ALL, true)) {
            throw Cannot_Validate_A_Registered_Claim::create($claim);
        }
    }
    public function assert(Token $token): void
    {
        if (!$token instanceof Unencrypted_Token) {
            throw Constraint_Violation::error('You should pass a plain token', $this);
        }
        $claims = $token->claims();
        if (!$claims->has($this->claim)) {
            throw Constraint_Violation::error('The token does not have the claim "' . $this->claim . '"', $this);
        }
        if ($claims->get($this->claim) !== $this->expected_value) {
            throw Constraint_Violation::error('The claim "' . $this->claim . '" does not have the expected value', $this);
        }
    }
}