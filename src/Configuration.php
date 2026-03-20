<?php

declare (strict_types=1);
namespace Lcobucci\JWT;

use Closure;
use Lcobucci\JWT\Encoding\Chained_Formatter;
use Lcobucci\JWT\Encoding\Jose_Encoder;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Validation\Constraint;
use No_Discard;
/**
 * Configuration container for the JWT Builder and Parser
 *
 * Serves like a small DI container to simplify the creation and usage
 * of the objects.
 */
final readonly class Configuration
{
    private Parser $parser;
    private Validator $validator;
    /** @var Closure(ClaimsFormatter $claimFormatter): Builder */
    private Closure $builder_factory;
    /** @var Constraint[] */
    private array $validation_constraints;
    /** @param Closure(ClaimsFormatter $claimFormatter): Builder|null $builderFactory */
    private function __construct(private Signer $signer, private Key $signing_key, private Key $verification_key, private Encoder $encoder, private Decoder $decoder, ?Parser $parser, ?Validator $validator, ?Closure $builder_factory, Constraint ...$validation_constraints)
    {
        $this->parser = $parser ?? new Token\Parser($decoder);
        $this->validator = $validator ?? new Validation\Validator();
        $this->builder_factory = $builder_factory ?? static fn(Claims_Formatter $claim_formatter): Builder => Token\Builder::new($encoder, $claim_formatter);
        $this->validation_constraints = $validation_constraints;
    }
    #[No_Discard]
    public static function for_asymmetric_signer(Signer $signer, Key $signing_key, Key $verification_key, Encoder $encoder = new Jose_Encoder(), Decoder $decoder = new Jose_Encoder()): self
    {
        return new self($signer, $signing_key, $verification_key, $encoder, $decoder, null, null, null);
    }
    #[No_Discard]
    public static function for_symmetric_signer(Signer $signer, Key $key, Encoder $encoder = new Jose_Encoder(), Decoder $decoder = new Jose_Encoder()): self
    {
        return new self($signer, $key, $key, $encoder, $decoder, null, null, null);
    }
    /** @param callable(ClaimsFormatter): Builder $builderFactory */
    #[No_Discard]
    public function with_builder_factory(callable $builder_factory): self
    {
        return new self($this->signer, $this->signing_key, $this->verification_key, $this->encoder, $this->decoder, $this->parser, $this->validator, $builder_factory(...), ...$this->validation_constraints);
    }
    public function builder(?Claims_Formatter $claim_formatter = null): Builder
    {
        return ($this->builder_factory)($claim_formatter ?? Chained_Formatter::default());
    }
    public function parser(): Parser
    {
        return $this->parser;
    }
    #[No_Discard]
    public function with_parser(Parser $parser): self
    {
        return new self($this->signer, $this->signing_key, $this->verification_key, $this->encoder, $this->decoder, $parser, $this->validator, $this->builder_factory, ...$this->validation_constraints);
    }
    public function signer(): Signer
    {
        return $this->signer;
    }
    public function signing_key(): Key
    {
        return $this->signing_key;
    }
    public function verification_key(): Key
    {
        return $this->verification_key;
    }
    public function validator(): Validator
    {
        return $this->validator;
    }
    #[No_Discard]
    public function with_validator(Validator $validator): self
    {
        return new self($this->signer, $this->signing_key, $this->verification_key, $this->encoder, $this->decoder, $this->parser, $validator, $this->builder_factory, ...$this->validation_constraints);
    }
    /** @return Constraint[] */
    public function validation_constraints(): array
    {
        return $this->validation_constraints;
    }
    #[No_Discard]
    public function with_validation_constraints(Constraint ...$validation_constraints): self
    {
        return new self($this->signer, $this->signing_key, $this->verification_key, $this->encoder, $this->decoder, $this->parser, $this->validator, $this->builder_factory, ...$validation_constraints);
    }
}