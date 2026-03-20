<?php

declare (strict_types=1);
namespace Lcobucci\JWT\Signer;

use Lcobucci\JWT\Signer\Ecdsa\Multibyte_String_Converter;
use Lcobucci\JWT\Signer\Ecdsa\Signature_Converter;
use const OPENSSL_KEYTYPE_EC;
abstract readonly class Ecdsa extends Open_Ssl
{
    public function __construct(private Signature_Converter $converter = new Multibyte_String_Converter())
    {
    }
    final public function sign(string $payload, Key $key): string
    {
        return $this->converter->from_asn1($this->create_signature($key, $payload), $this->point_length());
    }
    final public function verify(string $expected, string $payload, Key $key): bool
    {
        return $this->verify_signature($this->converter->to_asn1($expected, $this->point_length()), $payload, $key);
    }
    /** {@inheritDoc} */
    final protected function guard_against_incompatible_key(int $type, int $length_in_bits): void
    {
        if ($type !== OPENSSL_KEYTYPE_EC) {
            throw Invalid_Key_Provided::incompatible_key_type(self::KEY_TYPE_MAP[OPENSSL_KEYTYPE_EC], self::KEY_TYPE_MAP[$type] ?? 'unknown');
        }
        $expected_key_length = $this->expected_key_length();
        if ($length_in_bits !== $expected_key_length) {
            throw Invalid_Key_Provided::incompatible_key_length($expected_key_length, $length_in_bits);
        }
    }
    /**
     * @internal
     *
     * @return positive-int
     */
    abstract public function expected_key_length(): int;
    /**
     * Returns the length of each point in the signature, so that we can calculate and verify R and S points properly
     *
     * @internal
     *
     * @return positive-int
     */
    abstract public function point_length(): int;
}