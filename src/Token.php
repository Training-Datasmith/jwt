<?php

declare (strict_types=1);
namespace Lcobucci\JWT;

use DateTimeInterface;
use Lcobucci\JWT\Token\Data_Set;
use No_Discard;
/** @immutable */
interface Token
{
    /**
     * Returns the token headers
     */
    public function headers(): Data_Set;
    /**
     * Returns if the token is allowed to be used by the audience
     *
     * @param non-empty-string $audience
     */
    public function is_permitted_for(string $audience): bool;
    /**
     * Returns if the token has the given id
     *
     * @param non-empty-string $id
     */
    public function is_identified_by(string $id): bool;
    /**
     * Returns if the token has the given subject
     *
     * @param non-empty-string $subject
     */
    public function is_related_to(string $subject): bool;
    /**
     * Returns if the token was issued by any of given issuers
     *
     * @param non-empty-string ...$issuers
     */
    public function has_been_issued_by(string ...$issuers): bool;
    /**
     * Returns if the token was issued before of given time
     */
    public function has_been_issued_before(DateTimeInterface $now): bool;
    /**
     * Returns if the token minimum time is before than given time
     */
    public function is_minimum_time_before(DateTimeInterface $now): bool;
    /**
     * Returns if the token is expired
     */
    public function is_expired(DateTimeInterface $now): bool;
    /**
     * Returns an encoded representation of the token
     *
     * @return non-empty-string
     */
    #[No_Discard]
    public function to_string(): string;
}