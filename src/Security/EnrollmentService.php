<?php

declare(strict_types=1);

namespace Tavy315\SyliusTwoFactorPlugin\Security;

use OTPHP\TOTP;
use Tavy315\SyliusTwoFactorPlugin\Entity\User\TwoFactorUserInterface;
use Tavy315\SyliusTwoFactorPlugin\Exception\InvalidEnrollmentCode;

final class EnrollmentService
{
    public const TWO_FACTOR_ENROLLMENT = 'two_factor_enrollment';
    private const TOTP_LEEWAY = 20;

    public function __construct(
        private readonly RecoveryCodeGenerator $recoveryCodeGenerator,
        private readonly string $issuer = 'Sylius',
    ) {
    }

    public function generateSecret(): string
    {
        return TOTP::generate()->getSecret();
    }

    public function provisioningUri(TwoFactorUserInterface $user, string $secret): string
    {
        $totp = TOTP::create($secret);
        $totp->setLabel($user->getTwoFactorDisplayName());
        $totp->setIssuer($this->issuer);

        return $totp->getProvisioningUri();
    }

    /**
     * @return list<string>
     * @throws InvalidEnrollmentCode
     */
    public function confirmAuthenticator(TwoFactorUserInterface $user, string $secret, string $submittedCode): array
    {
        $code = preg_replace('/\s+/', '', $submittedCode) ?? '';

        if (
            $secret === ''
            || $code === ''
            || !TOTP::create($secret)->verify($code, null, self::TOTP_LEEWAY)
        ) {
            throw new InvalidEnrollmentCode('Invalid enrollment code.');
        }

        $recoveryCodes = $this->recoveryCodeGenerator->generate();

        $user->recordConfirmedAuthenticator($secret, $recoveryCodes);

        return $recoveryCodes;
    }
}
