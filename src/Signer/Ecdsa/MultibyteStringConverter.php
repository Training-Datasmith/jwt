<?php

declare (strict_types=1);
/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2018 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 *
 * @link https://github.com/web-token/jwt-framework/blob/v1.2/src/Component/Core/Util/ECSignature.php
 */
namespace Lcobucci\JWT\Signer\Ecdsa;

use function assert;
use function bin2hex;
use function dechex;
use function hex2bin;
use function hexdec;
use function is_string;
use function str_pad;
use const STR_PAD_LEFT;
use function strlen;
use function substr;
/**
 * ECDSA signature converter using ext-mbstring
 *
 * @internal
 */
final readonly class Multibyte_String_Converter implements Signature_Converter
{
    private const string ASN1_SEQUENCE = '30';
    private const string ASN1_INTEGER = '02';
    private const int ASN1_MAX_SINGLE_BYTE = 128;
    private const string ASN1_LENGTH_2BYTES = '81';
    private const string ASN1_BIG_INTEGER_LIMIT = '7f';
    private const string ASN1_NEGATIVE_INTEGER = '00';
    private const int BYTE_SIZE = 2;
    public function to_asn1(string $points, int $length): string
    {
        $points = bin2hex($points);
        if (self::octet_length($points) !== $length) {
            throw Conversion_Failed::invalid_length();
        }
        $point_r = self::prepare_positive_integer(substr($points, 0, $length));
        $point_s = self::prepare_positive_integer(substr($points, $length));
        $length_r = self::octet_length($point_r);
        $length_s = self::octet_length($point_s);
        $total_length = $length_r + $length_s + self::BYTE_SIZE + self::BYTE_SIZE;
        $length_prefix = $total_length > self::ASN1_MAX_SINGLE_BYTE ? self::ASN1_LENGTH_2BYTES : '';
        $asn1 = hex2bin(self::ASN1_SEQUENCE . $length_prefix . dechex($total_length) . self::ASN1_INTEGER . dechex($length_r) . $point_r . self::ASN1_INTEGER . dechex($length_s) . $point_s);
        assert(is_string($asn1));
        assert($asn1 !== '');
        return $asn1;
    }
    private static function octet_length(string $data): int
    {
        return (int) (strlen($data) / self::BYTE_SIZE);
    }
    private static function prepare_positive_integer(string $data): string
    {
        if (substr($data, 0, self::BYTE_SIZE) > self::ASN1_BIG_INTEGER_LIMIT) {
            return self::ASN1_NEGATIVE_INTEGER . $data;
        }
        while (substr($data, 0, self::BYTE_SIZE) === self::ASN1_NEGATIVE_INTEGER && substr($data, 2, self::BYTE_SIZE) <= self::ASN1_BIG_INTEGER_LIMIT) {
            $data = substr($data, 2);
        }
        return $data;
    }
    public function from_asn1(string $signature, int $length): string
    {
        $message = bin2hex($signature);
        $position = 0;
        if (self::read_asn1content($message, $position, self::BYTE_SIZE) !== self::ASN1_SEQUENCE) {
            throw Conversion_Failed::incorrect_start_sequence();
        }
        // @phpstan-ignore-next-line
        if (self::read_asn1content($message, $position, self::BYTE_SIZE) === self::ASN1_LENGTH_2BYTES) {
            $position += self::BYTE_SIZE;
        }
        $point_r = self::retrieve_positive_integer(self::read_asn1integer($message, $position));
        $point_s = self::retrieve_positive_integer(self::read_asn1integer($message, $position));
        $points = hex2bin(str_pad($point_r, $length, '0', STR_PAD_LEFT) . str_pad($point_s, $length, '0', STR_PAD_LEFT));
        assert(is_string($points));
        assert($points !== '');
        return $points;
    }
    private static function read_asn1content(string $message, int &$position, int $length): string
    {
        $content = substr($message, $position, $length);
        $position += $length;
        return $content;
    }
    private static function read_asn1integer(string $message, int &$position): string
    {
        if (self::read_asn1content($message, $position, self::BYTE_SIZE) !== self::ASN1_INTEGER) {
            throw Conversion_Failed::integer_expected();
        }
        $length = (int) hexdec(self::read_asn1content($message, $position, self::BYTE_SIZE));
        return self::read_asn1content($message, $position, $length * self::BYTE_SIZE);
    }
    private static function retrieve_positive_integer(string $data): string
    {
        while (substr($data, 0, self::BYTE_SIZE) === self::ASN1_NEGATIVE_INTEGER && substr($data, 2, self::BYTE_SIZE) > self::ASN1_BIG_INTEGER_LIMIT) {
            $data = substr($data, 2);
        }
        return $data;
    }
}