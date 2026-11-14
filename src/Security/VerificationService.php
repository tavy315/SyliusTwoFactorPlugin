<?php

declare(strict_types=1);

namespace Tavy315\SyliusTwoFactorPlugin\Security;

use Doctrine\DBAL\LockMode;
use Doctrine\ORM\EntityManagerInterface;
use Tavy315\SyliusTwoFactorPlugin\Entity\User\TwoFactorUserInterface;
use Tavy315\SyliusTwoFactorPlugin\Exception\InvalidTwoFactorCode;

final readonly class VerificationService
{
    public function __construct(
        private CodeVerifier $codeVerifier,
        private EntityManagerInterface $entityManager,
    ) {
    }

    public function verifyOrFail(TwoFactorUserInterface $user, string $submittedCode): CodeVerificationResult
    {
        $verification = $this->codeVerifier->verify($user, $submittedCode);

        if (!$verification->isValid()) {
            throw new InvalidTwoFactorCode('Invalid two-factor authentication code.');
        }

        if (!$verification->usesRecoveryCode()) {
            return $verification;
        }

        $consumed = $this->entityManager->getConnection()->transactional(function () use ($user, $verification): bool {
            $this->entityManager->refresh($user, LockMode::PESSIMISTIC_WRITE);

            if (!$user->isBackupCode($verification->code)) {
                return false;
            }

            $user->invalidateBackupCode($verification->code);
            $this->entityManager->flush();

            return true;
        });

        if (!$consumed) {
            throw new InvalidTwoFactorCode('Invalid two-factor authentication code.');
        }

        return $verification;
    }
}
