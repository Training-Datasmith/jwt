<?php

declare (strict_types=1);
namespace Lcobucci\JWT\Token;

use DateTimeInterface;
use function in_array;
use Lcobucci\JWT\Unencrypted_Token;
final readonly class Plain implements Unencrypted_Token
{
    public function __construct(private Data_Set $headers, private Data_Set $claims, private Signature $signature)
    {
    }
    public function headers(): Data_Set
    {
        return $this->headers;
    }
    public function claims(): Data_Set
    {
        return $this->claims;
    }
    public function signature(): Signature
    {
        return $this->signature;
    }
    public function payload(): string
    {
        return $this->headers->to_string() . '.' . $this->claims->to_string();
    }
    public function is_permitted_for(string $audience): bool
    {
        return in_array($audience, $this->claims->get(Registered_Claims::AUDIENCE, []), true);
    }
    public function is_identified_by(string $id): bool
    {
        return $this->claims->get(Registered_Claims::ID) === $id;
    }
    public function is_related_to(string $subject): bool
    {
        return $this->claims->get(Registered_Claims::SUBJECT) === $subject;
    }
    public function has_been_issued_by(string ...$issuers): bool
    {
        return in_array($this->claims->get(Registered_Claims::ISSUER), $issuers, true);
    }
    public function has_been_issued_before(DateTimeInterface $now): bool
    {
        return $now >= $this->claims->get(Registered_Claims::ISSUED_AT);
    }
    public function is_minimum_time_before(DateTimeInterface $now): bool
    {
        return $now >= $this->claims->get(Registered_Claims::NOT_BEFORE);
    }
    public function is_expired(DateTimeInterface $now): bool
    {
        if (!$this->claims->has(Registered_Claims::EXPIRATION_TIME)) {
            return false;
        }
        return $now >= $this->claims->get(Registered_Claims::EXPIRATION_TIME);
    }
    public function to_string(): string
    {
        return $this->headers->to_string() . '.' . $this->claims->to_string() . '.' . $this->signature->to_string();
    }
}