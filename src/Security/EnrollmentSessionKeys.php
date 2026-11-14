<?php

declare(strict_types=1);

namespace Tavy315\SyliusTwoFactorPlugin\Security;

use Tavy315\SyliusTwoFactorPlugin\Entity\User\TwoFactorUserInterface;

final class EnrollmentSessionKeys
{
    public static function enrollmentSecret(TwoFactorUserInterface $user, string $scope): string
    {
        return self::for($user, $scope, 'enrollment_secret');
    }

    public static function recoveryCodes(TwoFactorUserInterface $user, string $scope): string
    {
        return self::for($user, $scope, 'recovery_codes');
    }

    private static function for(TwoFactorUserInterface $user, string $scope, string $name): string
    {
        return \sprintf('two_factor.%s.%s.%s', $scope, hash('sha256', $user->getUserIdentifier()), $name);
    }
}
