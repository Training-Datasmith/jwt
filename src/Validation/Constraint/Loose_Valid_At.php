<?php

declare (strict_types=1);
namespace Lcobucci\JWT\Validation\Constraint;

use DateInterval;
use DateTimeInterface;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\Validation\Constraint_Violation;
use Lcobucci\JWT\Validation\Valid_At as ValidAtInterface;
use Psr\Clock\Clock_Interface as Clock;
final readonly class Loose_Valid_At implements Valid_At_Interface
{
    private DateInterval $leeway;
    public function __construct(private Clock $clock, ?DateInterval $leeway = null)
    {
        $this->leeway = $this->guard_leeway($leeway);
    }
    private function guard_leeway(?DateInterval $leeway): DateInterval
    {
        if ($leeway === null) {
            return new DateInterval('PT0S');
        }
        if ($leeway->invert === 1) {
            throw Leeway_Cannot_Be_Negative::create();
        }
        return $leeway;
    }
    public function assert(Token $token): void
    {
        $now = $this->clock->now();
        $this->assert_issue_time($token, $now->add($this->leeway));
        $this->assert_minimum_time($token, $now->add($this->leeway));
        $this->assert_expiration($token, $now->sub($this->leeway));
    }
    /** @throws ConstraintViolation */
    private function assert_expiration(Token $token, DateTimeInterface $now): void
    {
        if ($token->is_expired($now)) {
            throw Constraint_Violation::error('The token is expired', $this);
        }
    }
    /** @throws ConstraintViolation */
    private function assert_minimum_time(Token $token, DateTimeInterface $now): void
    {
        if (!$token->is_minimum_time_before($now)) {
            throw Constraint_Violation::error('The token cannot be used yet', $this);
        }
    }
    /** @throws ConstraintViolation */
    private function assert_issue_time(Token $token, DateTimeInterface $now): void
    {
        if (!$token->has_been_issued_before($now)) {
            throw Constraint_Violation::error('The token was issued in the future', $this);
        }
    }
}