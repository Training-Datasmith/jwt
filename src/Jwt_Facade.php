<?php

declare (strict_types=1);
namespace Lcobucci\JWT;

use function assert;
use Closure;
use DateTimeImmutable;
use Lcobucci\JWT\Encoding\Chained_Formatter;
use Lcobucci\JWT\Encoding\Jose_Encoder;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Validation\Constraint;
use Lcobucci\JWT\Validation\Signed_With;
use Lcobucci\JWT\Validation\Valid_At;
use Lcobucci\JWT\Validation\Validator;
use No_Discard;
use Psr\Clock\Clock_Interface as Clock;
final readonly class Jwt_Facade
{
    private Clock $clock;
    public function __construct(private Parser $parser = new Token\Parser(new Jose_Encoder()), ?Clock $clock = null)
    {
        $this->clock = $clock ?? new class implements Clock
        {
            public function now(): DateTimeImmutable
            {
                return new DateTimeImmutable();
            }
        };
    }
    /** @param Closure(Builder, DateTimeImmutable):Builder $customiseBuilder */
    #[No_Discard]
    public function issue(Signer $signer, Key $signing_key, Closure $customise_builder): Unencrypted_Token
    {
        $builder = Token\Builder::new(new Jose_Encoder(), Chained_Formatter::with_unix_timestamp_dates());
        $now = $this->clock->now();
        $builder = $builder->issued_at($now)->can_only_be_used_after($now)->expires_at($now->modify('+5 minutes'));
        return $customise_builder($builder, $now)->get_token($signer, $signing_key);
    }
    /** @param non-empty-string $jwt */
    #[No_Discard]
    public function parse(string $jwt, Signed_With $signed_with, Valid_At $valid_at, Constraint ...$constraints): Unencrypted_Token
    {
        $token = $this->parser->parse($jwt);
        assert($token instanceof Unencrypted_Token);
        (new Validator())->assert($token, $signed_with, $valid_at, ...$constraints);
        return $token;
    }
}