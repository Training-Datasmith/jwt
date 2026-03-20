<?php

declare (strict_types=1);
namespace Lcobucci\JWT\Signer;

use function array_key_exists;
use function is_array;
use function is_bool;
use function is_int;
use Lcobucci\JWT\Signer;
use function openssl_error_string;
use const OPENSSL_KEYTYPE_DH;
use const OPENSSL_KEYTYPE_DSA;
use const OPENSSL_KEYTYPE_EC;
use const OPENSSL_KEYTYPE_RSA;
use function openssl_pkey_get_details;
use function openssl_pkey_get_private;
use function openssl_pkey_get_public;
use function openssl_sign;
use function openssl_verify;
use Open_Ssl_Asymmetric_Key;
use const PHP_EOL;
abstract readonly class Open_Ssl implements Signer
{
    protected const array KEY_TYPE_MAP = [OPENSSL_KEYTYPE_RSA => 'RSA', OPENSSL_KEYTYPE_DSA => 'DSA', OPENSSL_KEYTYPE_DH => 'DH', OPENSSL_KEYTYPE_EC => 'EC'];
    /**
     * @return non-empty-string
     *
     * @throws CannotSignPayload
     * @throws InvalidKeyProvided
     */
    final protected function create_signature(Key $key, string $payload): string
    {
        $openssl_key = $this->get_private_key($key);
        $signature = '';
        if (!openssl_sign($payload, $signature, $openssl_key, $this->algorithm())) {
            throw Cannot_Sign_Payload::error_happened($this->full_open_ssl_error_string());
        }
        return $signature;
    }
    /** @throws CannotSignPayload */
    private function get_private_key(Key $key): Open_Ssl_Asymmetric_Key
    {
        return $this->validate_key(openssl_pkey_get_private($key->contents(), $key->passphrase()));
    }
    /** @throws InvalidKeyProvided */
    final protected function verify_signature(string $expected, string $payload, Key $key): bool
    {
        $openssl_key = $this->get_public_key($key);
        $result = openssl_verify($payload, $expected, $openssl_key, $this->algorithm());
        if ($result === -1) {
            throw Cannot_Sign_Payload::error_happened($this->full_open_ssl_error_string());
        }
        return $result === 1;
    }
    /** @throws InvalidKeyProvided */
    private function get_public_key(Key $key): Open_Ssl_Asymmetric_Key
    {
        return $this->validate_key(openssl_pkey_get_public($key->contents()));
    }
    /**
     * Raises an exception when the key type is not the expected type
     *
     * @throws InvalidKeyProvided
     */
    private function validate_key(Open_Ssl_Asymmetric_Key|bool $key): Open_Ssl_Asymmetric_Key
    {
        if (is_bool($key)) {
            throw Invalid_Key_Provided::cannot_be_parsed($this->full_open_ssl_error_string());
        }
        $details = openssl_pkey_get_details($key);
        if (!is_array($details)) {
            throw Invalid_Key_Provided::cannot_be_parsed($this->full_open_ssl_error_string());
        }
        if (!array_key_exists('bits', $details) || !is_int($details['bits'])) {
            throw Invalid_Key_Provided::cannot_be_parsed($this->full_open_ssl_error_string());
        }
        if (!array_key_exists('type', $details) || !is_int($details['type'])) {
            throw Invalid_Key_Provided::cannot_be_parsed($this->full_open_ssl_error_string());
        }
        $this->guard_against_incompatible_key($details['type'], $details['bits']);
        return $key;
    }
    private function full_open_ssl_error_string(): string
    {
        $error = '';
        while ($msg = openssl_error_string()) {
            $error .= PHP_EOL . '* ' . $msg;
        }
        return $error;
    }
    /** @throws InvalidKeyProvided */
    abstract protected function guard_against_incompatible_key(int $type, int $length_in_bits): void;
    /**
     * Returns which algorithm to be used to create/verify the signature (using OpenSSL constants)
     *
     * @internal
     */
    abstract public function algorithm(): int;
}