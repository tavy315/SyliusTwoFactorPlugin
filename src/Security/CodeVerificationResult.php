<?php

declare(strict_types=1);

namespace Tavy315\SyliusTwoFactorPlugin\Security;

final readonly class CodeVerificationResult
{
    public function __construct(
        public string $code,
        public CodeVerificationMethod $method,
    ) {
    }

    public function isValid(): bool
    {
        return $this->method !== CodeVerificationMethod::INVALID;
    }

    public function usesRecoveryCode(): bool
    {
        return $this->method === CodeVerificationMethod::RECOVERY_CODE;
    }
}
