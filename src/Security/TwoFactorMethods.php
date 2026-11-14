<?php

declare(strict_types=1);

namespace Tavy315\SyliusTwoFactorPlugin\Security;

use Sylius\Component\User\Model\UserInterface;
use Symfony\Component\HttpFoundation\Session\SessionInterface;
use Tavy315\SyliusTwoFactorPlugin\Entity\User\TwoFactorUserInterface;

final readonly class TwoFactorMethods
{
    public function __construct(
        public bool $totp = true,
        public bool $email = false,
    ) {
    }

    public function isEnabled(): bool
    {
        return $this->totp || $this->email;
    }

    public function isSatisfied(TwoFactorUserInterface $user, SessionInterface $session): bool
    {
        $verified = $session->get(SignInSessionKeys::key(SignInSessionKeys::TWO_FACTOR_VERIFIED, $user));
        if ($this->email && $verified === 'email') {
            return true;
        }

        if (!$this->totp || !$user->hasCompletedTwoFactorEnrollment()) {
            return false;
        }

        return $verified === 'totp'
            || (
                !$this->email
                && $verified === null
                && !$session->has(SignInSessionKeys::key(SignInSessionKeys::TWO_FACTOR_LOGIN_PENDING, $user))
                && !$session->has(SignInSessionKeys::TWO_FACTOR_LOGIN_PENDING)
            );
    }

    public function emailAddress(TwoFactorUserInterface $user): ?string
    {
        if (!$this->email || !$user instanceof UserInterface) {
            return null;
        }

        $address = $user->getEmail();

        return filter_var($address, \FILTER_VALIDATE_EMAIL) !== false ? $address : null;
    }
}
