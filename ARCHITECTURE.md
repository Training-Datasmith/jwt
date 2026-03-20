# Architecture: jwt

## Purpose
lcobucci/jwt — a PHP library for issuing and verifying JSON Web Tokens (JWT) per RFC 7519. Supports HMAC (HS256/384/512), RSA (RS/PS 256/384/512), ECDSA (ES256/384/512), EdDSA, and BLAKE2b signing algorithms.

## Directory Structure
```
src/
  Configuration.php              # Fluent builder for the JWT issuing/parsing context
  Jwt_Facade.php                 # Simplified static/instance facade
  Builder.php / Parser.php       # Token construction and parsing interfaces
  Encoder.php / Decoder.php      # Base64url encode/decode contracts
  Claims_Formatter.php           # Formats claim values for serialization
  Token/
    Builder.php                  # Fluent token builder (headers + claims)
    Parser.php                   # Parses JWT compact-serialization strings
    Plain.php                    # A signed or unsigned JWT token value object
    Signature.php                # Encapsulates the raw signature bytes
    Data_Set.php                 # Immutable map of JWT headers or claims
  Encoding/
    Jose_Encoder.php             # JOSE Base64url encoding
    Chained_Formatter.php        # Applies multiple claim formatters in sequence
    Microsecond_Based_Date_Conversion.php
    Unix_Timestamp_Dates.php
    Unify_Audience.php
  Signer/
    Hmac.php / Hmac/Sha{256,384,512}.php
    Ecdsa.php / Ecdsa/Sha{256,384,512}.php   # OpenSSL-backed ECDSA
    Open_SSL.php                              # Base for RSA/ECDSA via OpenSSL
    Eddsa.php                                # Ed25519 via libsodium
    Blake2b.php                              # BLAKE2b MAC via libsodium
    Key/In_Memory.php                        # Key material (PEM, DER, or raw bytes)
  Validation/
    Constraint.php               # Interface for claim validation rules
    Validator.php                # Runs a set of Constraints against a token
    Constraint/
      Has_Claim.php / Has_Claim_With_Value.php
      Identified_By.php / Issued_By.php / Permitted_For.php / Related_To.php
      Valid_At.php / Loose_Valid_At.php / Strict_Valid_At.php
      Signed_With.php / Signed_With_One_In_Set.php / Signed_With_Until_Date.php
  Exception.php                  # Base exception
tests/
```

## Key Design Decisions
- **Immutable token value objects** — `Plain` tokens are immutable after creation; the builder produces a new token, the parser produces a new token.
- **Signer/key separation** — signing algorithms and key material are separate objects; keys are passed to the signer at sign/verify time, not stored inside the signer.
- **Validation constraints** — claim validation is decomposed into small `Constraint` implementations, composed in a `Validator`. This allows mixing built-in and custom constraints.
- **Configuration as entry point** — `Configuration::forSymmetricSigner()` / `forAsymmetricSigner()` wires together the builder, parser, signer, and validator, providing a consistent context.

## Extension Points
- Implement `Signer` to add a new algorithm.
- Implement `Constraint` to add a custom claim validation rule.
- Implement `Claims_Formatter` to customise how specific claim values are serialized.
- Implement `Encoder`/`Decoder` to change the Base64 encoding scheme.

## Dependency Flow
```
Configuration::forSymmetricSigner(new Hmac\Sha256(), InMemory::plainText($secret))
  └─ Token\Builder → issue token
       └─ Signer::sign() → Plain token with Signature
  └─ Token\Parser → parse compact JWT string → Plain token
  └─ Validator::validate(Plain, Constraint[]) → bool
```
