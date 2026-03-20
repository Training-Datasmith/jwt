<?php

declare (strict_types=1);
namespace Lcobucci\JWT\Token;

use function array_diff;
use function array_merge;
use DateTimeImmutable;
use function in_array;
use Lcobucci\JWT\Builder as BuilderInterface;
use Lcobucci\JWT\Claims_Formatter;
use Lcobucci\JWT\Encoder;
use Lcobucci\JWT\Encoding\Cannot_Encode_Content;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Unencrypted_Token;
use No_Discard;
/** @immutable */
final readonly class Builder implements Builder_Interface
{
    /**
     * @param array<non-empty-string, mixed> $headers
     * @param array<non-empty-string, mixed> $claims
     */
    private function __construct(private Encoder $encoder, private Claims_Formatter $claim_formatter, private array $headers = ['typ' => 'JWT', 'alg' => null], private array $claims = [])
    {
    }
    #[No_Discard]
    public static function new(Encoder $encoder, Claims_Formatter $claim_formatter): self
    {
        return new self($encoder, $claim_formatter);
    }
    public function permitted_for(string ...$audiences): Builder_Interface
    {
        $configured = $this->claims[Registered_Claims::AUDIENCE] ?? [];
        $to_append = array_diff($audiences, $configured);
        return $this->new_with_claim(Registered_Claims::AUDIENCE, array_merge($configured, $to_append));
    }
    public function expires_at(DateTimeImmutable $expiration): Builder_Interface
    {
        return $this->new_with_claim(Registered_Claims::EXPIRATION_TIME, $expiration);
    }
    public function identified_by(string $id): Builder_Interface
    {
        return $this->new_with_claim(Registered_Claims::ID, $id);
    }
    public function issued_at(DateTimeImmutable $issued_at): Builder_Interface
    {
        return $this->new_with_claim(Registered_Claims::ISSUED_AT, $issued_at);
    }
    public function issued_by(string $issuer): Builder_Interface
    {
        return $this->new_with_claim(Registered_Claims::ISSUER, $issuer);
    }
    public function can_only_be_used_after(DateTimeImmutable $not_before): Builder_Interface
    {
        return $this->new_with_claim(Registered_Claims::NOT_BEFORE, $not_before);
    }
    public function related_to(string $subject): Builder_Interface
    {
        return $this->new_with_claim(Registered_Claims::SUBJECT, $subject);
    }
    public function with_header(string $name, mixed $value): Builder_Interface
    {
        $headers = $this->headers;
        $headers[$name] = $value;
        return new self($this->encoder, $this->claim_formatter, $headers, $this->claims);
    }
    public function with_claim(string $name, mixed $value): Builder_Interface
    {
        if (in_array($name, Registered_Claims::ALL, true)) {
            throw Registered_Claim_Given::for_claim($name);
        }
        return $this->new_with_claim($name, $value);
    }
    /** @param non-empty-string $name */
    private function new_with_claim(string $name, mixed $value): Builder_Interface
    {
        $claims = $this->claims;
        $claims[$name] = $value;
        return new self($this->encoder, $this->claim_formatter, $this->headers, $claims);
    }
    /**
     * @param array<non-empty-string, mixed> $items
     *
     * @throws CannotEncodeContent When data cannot be converted to JSON.
     */
    private function encode(array $items): string
    {
        return $this->encoder->base64url_encode($this->encoder->json_encode($items));
    }
    public function get_token(Signer $signer, Key $key): Unencrypted_Token
    {
        $headers = $this->headers;
        $headers['alg'] = $signer->algorithm_id();
        $encoded_headers = $this->encode($headers);
        $encoded_claims = $this->encode($this->claim_formatter->format_claims($this->claims));
        $signature = $signer->sign($encoded_headers . '.' . $encoded_claims, $key);
        $encoded_signature = $this->encoder->base64url_encode($signature);
        return new Plain(new Data_Set($headers, $encoded_headers), new Data_Set($this->claims, $encoded_claims), new Signature($signature, $encoded_signature));
    }
}