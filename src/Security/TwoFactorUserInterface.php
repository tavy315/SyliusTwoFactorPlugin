<?php

declare(strict_types=1);

namespace Tavy315\SyliusTwoFactorPlugin\Security;

use Symfony\Component\Security\Core\User\UserInterface;

interface TwoFactorUserInterface extends UserInterface
{
    public function acknowledgeTwoFactorRecoveryCodes(): void;

    public function recordConfirmedAuthenticator(string $secret, array $recoveryCodes): void;

    public function getTwoFactorDisplayName(): string;

    public function getTwoFactorTotpSecret(): ?string;

    public function getUserIdentifier(): string;

    public function hasCompletedTwoFactorEnrollment(): bool;

    public function invalidateBackupCode(string $code): void;

    public function isBackupCode(string $code): bool;

    public function restartIncompleteTwoFactorEnrollment(): void;
}
