<?php

declare(strict_types=1);

namespace Tavy315\SyliusTwoFactorPlugin\Tests;

use OTPHP\TOTP;
use PHPUnit\Framework\TestCase;
use Tavy315\SyliusTwoFactorPlugin\Tests\Fixture\AdminUser;

final class TwoFactorUserTest extends TestCase
{
    public function testEnrollmentEncryptsTheSecretAndConsumesRecoveryCodes(): void
    {
        $user = new AdminUser();
        $user->setEmail('admin@example.com');
        $secret = TOTP::generate()->getSecret();

        $user->recordConfirmedAuthenticator($secret, ['ABCD-EFGH']);

        self::assertFalse($user->hasCompletedTwoFactorEnrollment());
        self::assertSame($secret, $user->getTwoFactorTotpSecret());
        $encryptedSecret = (new \ReflectionProperty($user, 'twoFactorTotpSecret'))->getValue($user);
        self::assertNotSame($secret, $encryptedSecret);

        $user->acknowledgeTwoFactorRecoveryCodes();

        self::assertTrue($user->isBackupCode('ABCD-EFGH'));

        $user->invalidateBackupCode('ABCD-EFGH');

        self::assertTrue($user->hasCompletedTwoFactorEnrollment());
        self::assertFalse($user->isBackupCode('ABCD-EFGH'));
    }

    public function testIncompleteEnrollmentCanBeRestarted(): void
    {
        $user = new AdminUser();
        $user->setEmail('admin@example.com');

        $user->recordConfirmedAuthenticator(TOTP::generate()->getSecret(), ['ABCD-EFGH']);
        $user->restartIncompleteTwoFactorEnrollment();

        self::assertNull($user->getTwoFactorTotpSecret());
        self::assertFalse($user->hasCompletedTwoFactorEnrollment());
    }

    public function testCompletedEnrollmentCannotBeRestarted(): void
    {
        $user = new AdminUser();
        $user->setEmail('admin@example.com');
        $user->recordConfirmedAuthenticator(TOTP::generate()->getSecret(), ['ABCD-EFGH']);
        $user->acknowledgeTwoFactorRecoveryCodes();

        $this->expectException(\LogicException::class);
        $user->restartIncompleteTwoFactorEnrollment();
    }
}
