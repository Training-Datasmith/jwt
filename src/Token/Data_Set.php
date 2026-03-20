<?php

declare (strict_types=1);
namespace Lcobucci\JWT\Token;

use function array_key_exists;
/**
 * An immutable value object holding a JWT header or claims set.
 *
 * Stores the decoded data as an associative array and preserves the original
 * Base64URL-encoded string so the signature can be verified against the exact bytes.
 */
final readonly class Data_Set
{
    /**
     * @param array<non-empty-string, mixed> $data    Decoded key-value pairs (claims or headers).
     * @param string                         $encoded Base64URL-encoded representation (no padding).
     */
    public function __construct(private array $data, private string $encoded)
    {
    }

    /**
     * Return the value of a single claim or header by name.
     *
     * @param  non-empty-string $name    The claim/header name (e.g. 'iss', 'sub', 'alg').
     * @param  mixed            $default Value returned if the key is absent.
     * @return mixed                     The stored value or $default.
     */
    public function get(string $name, mixed $default = null): mixed
    {
        return $this->data[$name] ?? $default;
    }

    /**
     * Return whether the data set contains the given claim or header name.
     *
     * @param  non-empty-string $name The claim/header name to check.
     * @return bool                   True if present (even if the value is null).
     */
    public function has(string $name): bool
    {
        return array_key_exists($name, $this->data);
    }

    /**
     * Return all decoded key-value pairs.
     *
     * @return array<non-empty-string, mixed>
     */
    public function all(): array
    {
        return $this->data;
    }

    /**
     * Return the original Base64URL-encoded string for signature verification.
     *
     * @return string The encoded representation as it appeared in the JWT compact serialization.
     */
    public function to_string(): string
    {
        return $this->encoded;
    }
}