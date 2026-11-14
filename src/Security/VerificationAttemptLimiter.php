<?php

declare(strict_types=1);

namespace Tavy315\SyliusTwoFactorPlugin\Security;

use Symfony\Component\RateLimiter\RateLimiterFactory;
use Tavy315\SyliusTwoFactorPlugin\Entity\User\TwoFactorUserInterface;

final readonly class VerificationAttemptLimiter
{
    public function __construct(
        private RateLimiterFactory $twoFactorVerificationUserLimiter,
        private RateLimiterFactory $twoFactorVerificationIpLimiter,
    ) {
    }

    public function consume(TwoFactorUserInterface $user, ?string $ipAddress, string $purpose = 'totp'): bool
    {
        $prefix = $purpose === 'totp' ? '' : $purpose . ':';
        $userLimit = $this->twoFactorVerificationUserLimiter->create(
            hash('sha256', $prefix . $user::class . ':' . $user->getUserIdentifier()),
        )->consume();
        $ipLimit = $this->twoFactorVerificationIpLimiter->create(
            hash('sha256', $prefix . ($ipAddress ?? 'unknown')),
        )->consume();

        return $userLimit->isAccepted() && $ipLimit->isAccepted();
    }
}
