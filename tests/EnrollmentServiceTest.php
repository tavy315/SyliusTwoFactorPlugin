<?php

declare(strict_types=1);

namespace Tavy315\SyliusTwoFactorPlugin\Tests;

use OTPHP\TOTP;
use PHPUnit\Framework\TestCase;
use Tavy315\SyliusTwoFactorPlugin\Entity\User\TwoFactorUserInterface;
use Tavy315\SyliusTwoFactorPlugin\Exception\InvalidEnrollmentCode;
use Tavy315\SyliusTwoFactorPlugin\Security\EnrollmentService;
use Tavy315\SyliusTwoFactorPlugin\Security\RecoveryCodeGenerator;

final class EnrollmentServiceTest extends TestCase
{
    public function testItCompletesEnrollmentWithAValidTotpCode(): void
    {
        $secret = TOTP::generate()->getSecret();
        $recoveryCodes = ['ABCD-EFGH'];

        $generator = $this->createMock(RecoveryCodeGenerator::class);
        $generator->expects(self::once())->method('generate')->willReturn($recoveryCodes);

        $user = $this->createMock(TwoFactorUserInterface::class);
        $user->expects(self::once())->method('recordConfirmedAuthenticator')->with($secret, $recoveryCodes);

        $enrollmentService = new EnrollmentService($generator);
        $result = $enrollmentService->confirmAuthenticator($user, $secret, ' ' . TOTP::create($secret)->now() . ' ');

        self::assertSame($recoveryCodes, $result);
    }

    public function testItRejectsAnInvalidCodeWithoutEnrollingTheUser(): void
    {
        $generator = $this->createMock(RecoveryCodeGenerator::class);
        $generator->expects(self::never())->method('generate');

        $user = $this->createMock(TwoFactorUserInterface::class);
        $user->expects(self::never())->method('recordConfirmedAuthenticator');

        $this->expectException(InvalidEnrollmentCode::class);

        $enrollmentService = new EnrollmentService($generator);
        $enrollmentService->confirmAuthenticator($user, 'secret', 'invalid');
    }

    public function testItBuildsAProvisioningUriForTheUser(): void
    {
        $generator = $this->createMock(RecoveryCodeGenerator::class);

        $user = $this->createMock(TwoFactorUserInterface::class);
        $user->method('getTwoFactorDisplayName')->willReturn('user@example.com');

        $enrollmentService = new EnrollmentService($generator, 'Example Store');
        $uri = $enrollmentService->provisioningUri($user, 'JBSWY3DPEHPK3PXP');

        self::assertStringStartsWith('otpauth://totp/', $uri);
        self::assertStringContainsString('issuer=Example%20Store', $uri);
        self::assertStringContainsString('secret=JBSWY3DPEHPK3PXP', $uri);
    }
}
