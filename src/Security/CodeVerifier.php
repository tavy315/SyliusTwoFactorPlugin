<?php

declare(strict_types=1);

namespace Tavy315\SyliusTwoFactorPlugin\Security;

use OTPHP\TOTP;

final class CodeVerifier
{
    public function verify(TwoFactorUserInterface $user, string $submittedCode): CodeVerificationResult
    {
        $code = preg_replace('/\s+/', '', $submittedCode) ?? '';

        if ($code === '') {
            return new CodeVerificationResult($code, CodeVerificationMethod::INVALID);
        }

        $secret = $user->getTwoFactorTotpSecret();

        if (
            $secret !== null
            && $secret !== ''
            && TOTP::create($secret)->verify($code, null, 20)
        ) {
            return new CodeVerificationResult($code, CodeVerificationMethod::TOTP);
        }

        return new CodeVerificationResult(
            $code,
            $user->isBackupCode($code) ? CodeVerificationMethod::RECOVERY_CODE : CodeVerificationMethod::INVALID,
        );
    }
}
