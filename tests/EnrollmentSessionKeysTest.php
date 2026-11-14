<?php

declare(strict_types=1);

namespace Tavy315\SyliusTwoFactorPlugin\Tests;

use PHPUnit\Framework\TestCase;
use Tavy315\SyliusTwoFactorPlugin\Entity\User\TwoFactorUserInterface;
use Tavy315\SyliusTwoFactorPlugin\Security\EnrollmentSessionKeys;

final class EnrollmentSessionKeysTest extends TestCase
{
    public function testItNamespacesKeysByScopeAndUser(): void
    {
        $shopUser = $this->createMock(TwoFactorUserInterface::class);
        $shopUser->method('getUserIdentifier')->willReturn('shop@example.com');

        $adminUser = $this->createMock(TwoFactorUserInterface::class);
        $adminUser->method('getUserIdentifier')->willReturn('admin@example.com');

        self::assertNotSame(
            EnrollmentSessionKeys::enrollmentSecret($shopUser, 'shop'),
            EnrollmentSessionKeys::enrollmentSecret($shopUser, 'admin'),
        );
        self::assertNotSame(
            EnrollmentSessionKeys::enrollmentSecret($shopUser, 'shop'),
            EnrollmentSessionKeys::enrollmentSecret($adminUser, 'shop'),
        );
        self::assertNotSame(
            EnrollmentSessionKeys::enrollmentSecret($shopUser, 'shop'),
            EnrollmentSessionKeys::recoveryCodes($shopUser, 'shop'),
        );
    }
}
