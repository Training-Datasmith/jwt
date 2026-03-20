<?php

declare (strict_types=1);
namespace Lcobucci\JWT\Signer\Key;

use function assert;
use function is_string;
use Lcobucci\JWT\Signer\Invalid_Key_Provided;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Sodium_Base64polyfill;
use Sensitive_Parameter;
use Spl_File_Object;
use Throwable;
final readonly class In_Memory implements Key
{
    /** @param non-empty-string $contents */
    private function __construct(
        #[Sensitive_Parameter]
        public string $contents,
        #[Sensitive_Parameter]
        public string $passphrase
    )
    {
    }
    /** @param non-empty-string $contents */
    public static function plain_text(
        #[Sensitive_Parameter]
        string $contents,
        #[Sensitive_Parameter]
        string $passphrase = ''
    ): self
    {
        self::guard_against_empty_key($contents);
        // @phpstan-ignore staticMethod.alreadyNarrowedType
        return new self($contents, $passphrase);
    }
    /** @param non-empty-string $contents */
    public static function base64Encoded(
        #[Sensitive_Parameter]
        string $contents,
        #[Sensitive_Parameter]
        string $passphrase = ''
    ): self
    {
        $decoded = Sodium_Base64polyfill::base642bin($contents, Sodium_Base64polyfill::SODIUM_BASE64_VARIANT_ORIGINAL);
        self::guard_against_empty_key($decoded);
        // @phpstan-ignore staticMethod.alreadyNarrowedType
        return new self($decoded, $passphrase);
    }
    /**
     * @param non-empty-string $path
     *
     * @throws FileCouldNotBeRead
     */
    public static function file(
        string $path,
        #[Sensitive_Parameter]
        string $passphrase = ''
    ): self
    {
        try {
            $file = new Spl_File_Object($path);
        } catch (Throwable $exception) {
            throw File_Could_Not_Be_Read::on_path($path, $exception);
        }
        $file_size = $file->get_size();
        $contents = $file_size > 0 ? $file->fread($file->get_size()) : '';
        assert(is_string($contents));
        self::guard_against_empty_key($contents);
        return new self($contents, $passphrase);
    }
    /** @phpstan-assert non-empty-string $contents */
    private static function guard_against_empty_key(string $contents): void
    {
        if ($contents === '') {
            throw Invalid_Key_Provided::cannot_be_empty();
        }
    }
    public function contents(): string
    {
        return $this->contents;
    }
    public function passphrase(): string
    {
        return $this->passphrase;
    }
}