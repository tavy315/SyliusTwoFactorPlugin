<?php

declare(strict_types=1);

namespace Tavy315\SyliusTwoFactorPlugin\Security;

final class SignInSessionKeys
{
    public const TWO_FACTOR_LOGIN_PENDING = 'two_factor.login_pending';
    public const TWO_FACTOR_LOGIN_TARGET = 'two_factor.login_target';

    public const TWO_FACTOR_VERIFIED = 'two_factor.verified';
    public const TWO_FACTOR_EMAIL_CHALLENGE = 'two_factor.email_challenge';

    public static function key(string $key, TwoFactorUserInterface $user): string
    {
        return $key . '.' . hash('sha256', $user::class . ':' . $user->getUserIdentifier());
    }
}
