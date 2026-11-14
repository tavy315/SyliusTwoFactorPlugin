<?php

declare(strict_types=1);

namespace Tavy315\SyliusTwoFactorPlugin\Tests;

use Doctrine\DBAL\Connection;
use Doctrine\DBAL\LockMode;
use Doctrine\ORM\EntityManagerInterface;
use PHPUnit\Framework\TestCase;
use Tavy315\SyliusTwoFactorPlugin\Entity\User\TwoFactorUserInterface;
use Tavy315\SyliusTwoFactorPlugin\Exception\InvalidTwoFactorCode;
use Tavy315\SyliusTwoFactorPlugin\Security\CodeVerificationMethod;
use Tavy315\SyliusTwoFactorPlugin\Security\CodeVerifier;
use Tavy315\SyliusTwoFactorPlugin\Security\VerificationService;

final class VerificationServiceTest extends TestCase
{
    public function testItConsumesARecoveryCodeAndFlushes(): void
    {
        $user = $this->createMock(TwoFactorUserInterface::class);
        $user->method('getTwoFactorTotpSecret')->willReturn(null);
        $user->method('isBackupCode')->with('ABCD-EFGH')->willReturn(true);
        $user->expects(self::once())->method('invalidateBackupCode')->with('ABCD-EFGH');

        $entityManager = $this->createMock(EntityManagerInterface::class);
        $entityManager->method('getConnection')->willReturn($this->transactionConnection());
        $entityManager->expects(self::once())->method('refresh')->with($user, LockMode::PESSIMISTIC_WRITE);
        $entityManager->expects(self::once())->method('flush');

        $verificationService = new VerificationService(new CodeVerifier(), $entityManager);
        $result = $verificationService->verifyOrFail($user, 'ABCD-EFGH');

        self::assertSame(CodeVerificationMethod::RECOVERY_CODE, $result->method);
    }

    public function testItRejectsACodeConsumedByAnotherRequest(): void
    {
        $user = $this->createMock(TwoFactorUserInterface::class);
        $user->expects(self::exactly(2))->method('isBackupCode')->with('ABCD-EFGH')->willReturn(true, false);
        $user->expects(self::never())->method('invalidateBackupCode');

        $entityManager = $this->createMock(EntityManagerInterface::class);
        $entityManager->method('getConnection')->willReturn($this->transactionConnection());
        $entityManager->expects(self::once())->method('refresh')->with($user, LockMode::PESSIMISTIC_WRITE);
        $entityManager->expects(self::never())->method('flush');

        $this->expectException(InvalidTwoFactorCode::class);

        (new VerificationService(new CodeVerifier(), $entityManager))->verifyOrFail($user, 'ABCD-EFGH');
    }

    public function testItDoesNotFlushForAnInvalidCode(): void
    {
        $user = $this->createMock(TwoFactorUserInterface::class);
        $user->method('getTwoFactorTotpSecret')->willReturn(null);
        $user->method('isBackupCode')->with('invalid')->willReturn(false);
        $user->expects(self::never())->method('invalidateBackupCode');

        $entityManager = $this->createMock(EntityManagerInterface::class);
        $entityManager->expects(self::never())->method('flush');

        $this->expectException(InvalidTwoFactorCode::class);

        $verificationService = new VerificationService(new CodeVerifier(), $entityManager);
        $verificationService->verifyOrFail($user, 'invalid');
    }

    private function transactionConnection(): Connection
    {
        $connection = $this->createMock(Connection::class);
        $connection->expects(self::once())->method('transactional')->willReturnCallback(
            static fn (\Closure $operation): bool => $operation(),
        );

        return $connection;
    }
}
