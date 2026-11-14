<?php

declare(strict_types=1);

namespace Tavy315\SyliusTwoFactorPlugin\Entity\User;

use Doctrine\ORM\Mapping as ORM;
use Tavy315\SyliusTwoFactorPlugin\Security\TwoFactorSecretCipher;

trait TwoFactorUserTrait
{
    /** @ORM\Column(type="text", nullable=true) */
    private ?string $twoFactorTotpSecret = null;

    /** @ORM\Column(type="json", nullable=true) */
    private ?array $twoFactorRecoveryCodes = null;

    /** @ORM\Column(type="datetime", nullable=true) */
    private ?\DateTimeInterface $twoFactorEnrolledAt = null;

    /** @ORM\Column(name="two_factor_acknowledged_at", type="datetime", nullable=true) */
    private ?\DateTimeInterface $twoFactorAcknowledgedAt = null;

    public function acknowledgeTwoFactorRecoveryCodes(): void
    {
        if ($this->twoFactorTotpSecret === null) {
            throw new \LogicException('A two-factor secret must be configured before recovery codes can be acknowledged.');
        }

        $this->twoFactorAcknowledgedAt = new \DateTimeImmutable();
    }

    public function getTwoFactorDisplayName(): string
    {
        return (string) ($this->getEmail() ?? $this->getUsername());
    }

    public function getTwoFactorTotpSecret(): ?string
    {
        if ($this->twoFactorTotpSecret === null) {
            return null;
        }

        return TwoFactorSecretCipher::decrypt($this->twoFactorTotpSecret);
    }

    public function hasCompletedTwoFactorEnrollment(): bool
    {
        return $this->twoFactorTotpSecret !== null && $this->twoFactorEnrolledAt !== null && $this->twoFactorAcknowledgedAt !== null;
    }

    public function invalidateBackupCode(string $code): void
    {
        $this->twoFactorRecoveryCodes = array_values(array_filter(
            $this->twoFactorRecoveryCodes ?? [],
            static fn (string $recoveryCode): bool => !password_verify($code, $recoveryCode),
        ));
    }

    public function isBackupCode(string $code): bool
    {
        if (!$this->hasCompletedTwoFactorEnrollment()) {
            return false;
        }

        foreach ($this->twoFactorRecoveryCodes ?? [] as $recoveryCode) {
            if (password_verify($code, $recoveryCode)) {
                return true;
            }
        }

        return false;
    }

    public function recordConfirmedAuthenticator(string $secret, array $recoveryCodes): void
    {
        $this->twoFactorTotpSecret = TwoFactorSecretCipher::encrypt($secret);
        $this->twoFactorRecoveryCodes = array_map(
            static fn (string $code): string => password_hash($code, PASSWORD_DEFAULT),
            $recoveryCodes,
        );
        $this->twoFactorEnrolledAt = new \DateTimeImmutable();
        $this->twoFactorAcknowledgedAt = null;
    }

    public function restartIncompleteTwoFactorEnrollment(): void
    {
        if ($this->hasCompletedTwoFactorEnrollment()) {
            throw new \LogicException('A completed two-factor enrollment cannot be restarted.');
        }

        $this->twoFactorTotpSecret = null;
        $this->twoFactorRecoveryCodes = null;
        $this->twoFactorEnrolledAt = null;
        $this->twoFactorAcknowledgedAt = null;
    }
}
