<?php

declare (strict_types=1);
namespace Lcobucci\JWT\Validation;

use function array_map;
use function implode;
use Lcobucci\JWT\Exception;
use RuntimeException;
final class Required_Constraints_Violated extends RuntimeException implements Exception
{
    /** @param ConstraintViolation[] $violations */
    public function __construct(string $message = '', public readonly array $violations = [])
    {
        parent::__construct($message);
    }
    public static function from_violations(Constraint_Violation ...$violations): self
    {
        return new self(message: self::build_message($violations), violations: $violations);
    }
    /** @param ConstraintViolation[] $violations */
    private static function build_message(array $violations): string
    {
        $violations = array_map(static fn(Constraint_Violation $violation): string => '- ' . $violation->get_message(), $violations);
        $message = "The token violates some mandatory constraints, details:\n";
        return $message . implode("\n", $violations);
    }
    /** @return ConstraintViolation[] */
    public function violations(): array
    {
        return $this->violations;
    }
}