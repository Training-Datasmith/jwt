<?php

declare(strict_types=1);

/**
 * Example: issue and verify a JWT using HMAC-SHA256.
 *
 * Run from the jwt project root:
 *   php examples/issue_and_verify.php
 */

require __DIR__ . '/../vendor/autoload.php';

use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Hmac\Sha256;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Validation\Constraint\IssuedBy;
use Lcobucci\JWT\Validation\Constraint\PermittedFor;

$config = Configuration::forSymmetricSigner(
    new Sha256(),
    InMemory::plainText('super-secret-key-at-least-32-bytes!')
);

// --- Issue a token ---
$now = new DateTimeImmutable();
$token = $config->builder()
    ->issuedBy('https://example.com')
    ->permittedFor('https://api.example.com')
    ->issuedAt($now)
    ->expiresAt($now->modify('+1 hour'))
    ->withClaim('uid', 42)
    ->getToken($config->signer(), $config->signingKey());

$tokenString = $token->toString();
echo "Issued token:\n" . $tokenString . "\n\n";

// --- Parse the token string ---
$parsed = $config->parser()->parse($tokenString);

// --- Validate claims ---
$constraints = [
    new IssuedBy('https://example.com'),
    new PermittedFor('https://api.example.com'),
];

if ($config->validator()->validate($parsed, ...$constraints)) {
    echo "Token is valid!\n";
    echo "User ID: " . $parsed->claims()->get('uid') . "\n";
} else {
    echo "Token validation failed.\n";
}
