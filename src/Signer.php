<?php

declare (strict_types=1);
namespace Lcobucci\JWT;

use Lcobucci\JWT\Signer\Cannot_Sign_Payload;
use Lcobucci\JWT\Signer\Ecdsa\Conversion_Failed;
use Lcobucci\JWT\Signer\Invalid_Key_Provided;
use Lcobucci\JWT\Signer\Key;
use No_Discard;
/** @immutable */
interface Signer
{
    /**
     * Returns the algorithm id
     *
     * @return non-empty-string
     */
    public function algorithm_id(): string;
    /**
     * Creates a hash for the given payload
     *
     * @param non-empty-string $payload
     *
     * @return non-empty-string
     *
     * @throws CannotSignPayload  When payload signing fails.
     * @throws InvalidKeyProvided When issue key is invalid/incompatible.
     * @throws ConversionFailed   When signature could not be converted.
     */
    #[No_Discard]
    public function sign(string $payload, Key $key): string;
    /**
     * Returns if the expected hash matches with the data and key
     *
     * @param non-empty-string $expected
     * @param non-empty-string $payload
     *
     * @throws InvalidKeyProvided When issue key is invalid/incompatible.
     * @throws ConversionFailed   When signature could not be converted.
     */
    #[No_Discard]
    public function verify(string $expected, string $payload, Key $key): bool;
}