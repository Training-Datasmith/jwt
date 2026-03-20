<?php

declare (strict_types=1);
namespace Lcobucci\JWT;

use DateTimeImmutable;
use Lcobucci\JWT\Encoding\Cannot_Encode_Content;
use Lcobucci\JWT\Signer\Cannot_Sign_Payload;
use Lcobucci\JWT\Signer\Ecdsa\Conversion_Failed;
use Lcobucci\JWT\Signer\Invalid_Key_Provided;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Token\Registered_Claim_Given;
use No_Discard;
/** @immutable */
interface Builder
{
    /**
     * Appends new items to audience
     *
     * @param non-empty-string ...$audiences
     */
    #[No_Discard]
    public function permitted_for(string ...$audiences): Builder;
    /**
     * Configures the expiration time
     */
    #[No_Discard]
    public function expires_at(DateTimeImmutable $expiration): Builder;
    /**
     * Configures the token id
     *
     * @param non-empty-string $id
     */
    #[No_Discard]
    public function identified_by(string $id): Builder;
    /**
     * Configures the time that the token was issued
     */
    #[No_Discard]
    public function issued_at(DateTimeImmutable $issued_at): Builder;
    /**
     * Configures the issuer
     *
     * @param non-empty-string $issuer
     */
    #[No_Discard]
    public function issued_by(string $issuer): Builder;
    /**
     * Configures the time before which the token cannot be accepted
     */
    #[No_Discard]
    public function can_only_be_used_after(DateTimeImmutable $not_before): Builder;
    /**
     * Configures the subject
     *
     * @param non-empty-string $subject
     */
    #[No_Discard]
    public function related_to(string $subject): Builder;
    /**
     * Configures a header item
     *
     * @param non-empty-string $name
     */
    #[No_Discard]
    public function with_header(string $name, mixed $value): Builder;
    /**
     * Configures a claim item
     *
     * @param non-empty-string $name
     *
     * @throws RegisteredClaimGiven When trying to set a registered claim.
     */
    #[No_Discard]
    public function with_claim(string $name, mixed $value): Builder;
    /**
     * Returns a signed token to be used
     *
     * @throws CannotEncodeContent When data cannot be converted to JSON.
     * @throws CannotSignPayload   When payload signing fails.
     * @throws InvalidKeyProvided  When issue key is invalid/incompatible.
     * @throws ConversionFailed    When signature could not be converted.
     */
    #[No_Discard]
    public function get_token(Signer $signer, Key $key): Unencrypted_Token;
}