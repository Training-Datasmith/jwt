<?php

declare (strict_types=1);
namespace Lcobucci\JWT\Validation\Constraint;

use DateTimeImmutable;
use DateTimeInterface;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\Validation\Constraint_Violation;
use Lcobucci\JWT\Validation\Signed_With as SignedWithInterface;
use Psr\Clock\Clock_Interface;
final readonly class Signed_With_Until_Date implements Signed_With_Interface
{
    private Signed_With $verify_signature;
    private Clock_Interface $clock;
    public function __construct(Signer $signer, Signer\Key $key, private DateTimeImmutable $valid_until, ?Clock_Interface $clock = null)
    {
        $this->verify_signature = new Signed_With($signer, $key);
        $this->clock = $clock ?? new class implements Clock_Interface
        {
            public function now(): DateTimeImmutable
            {
                return new DateTimeImmutable();
            }
        };
    }
    public function assert(Token $token): void
    {
        if ($this->valid_until < $this->clock->now()) {
            throw Constraint_Violation::error('This constraint was only usable until ' . $this->valid_until->format(DateTimeInterface::RFC3339), $this);
        }
        $this->verify_signature->assert($token);
    }
}