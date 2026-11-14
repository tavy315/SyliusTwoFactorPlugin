<?php

declare(strict_types=1);

namespace Tavy315\SyliusTwoFactorPlugin\Tests;

use OTPHP\TOTP;
use PHPUnit\Framework\TestCase;
use Tavy315\SyliusTwoFactorPlugin\Entity\User\TwoFactorUserInterface;
use Tavy315\SyliusTwoFactorPlugin\Security\CodeVerificationMethod;
use Tavy315\SyliusTwoFactorPlugin\Security\CodeVerifier;

final class CodeVerifierTest extends TestCase
{
    public function testItAcceptsAndNormalizesTheCurrentTotpCode(): void
    {
        $secret = TOTP::generate()->getSecret();
        $user = $this->createMock(TwoFactorUserInterface::class);
        $user->method('getTwoFactorTotpSecret')->willReturn($secret);

        $result = (new CodeVerifier())->verify($user, ' ' . TOTP::create($secret)->now() . ' ');

        self::assertSame(CodeVerificationMethod::TOTP, $result->method);
        self::assertTrue($result->isValid());
        self::assertFalse($result->usesRecoveryCode());
    }

    public function testItAcceptsARecoveryCodeWhenTotpIsUnavailable(): void
    {
        $user = $this->createMock(TwoFactorUserInterface::class);
        $user->method('getTwoFactorTotpSecret')->willReturn(null);
        $user->method('isBackupCode')->with('ABCD-EFGH')->willReturn(true);

        $result = (new CodeVerifier())->verify($user, 'ABCD-EFGH');

        self::assertSame(CodeVerificationMethod::RECOVERY_CODE, $result->method);
        self::assertSame('ABCD-EFGH', $result->code);
        self::assertTrue($result->usesRecoveryCode());
    }

    public function testItRejectsAnEmptyCodeWithoutCheckingRecoveryCodes(): void
    {
        $user = $this->createMock(TwoFactorUserInterface::class);
        $user->expects(self::never())->method('isBackupCode');

        $result = (new CodeVerifier())->verify($user, " \n");

        self::assertSame(CodeVerificationMethod::INVALID, $result->method);
        self::assertFalse($result->isValid());
    }
}
