<?php

declare(strict_types=1);

namespace Tavy315\SyliusTwoFactorPlugin\Controller;

use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Security\Core\Exception\AccessDeniedException;
use Symfony\Component\Security\Core\Security;
use Symfony\Component\Security\Csrf\CsrfToken;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;
use Tavy315\SyliusTwoFactorPlugin\Security\EnrollmentSessionKeys;
use Tavy315\SyliusTwoFactorPlugin\Security\SignInSessionKeys;
use Tavy315\SyliusTwoFactorPlugin\Security\TwoFactorUserInterface;

final readonly class AcknowledgementController
{
    public const TWO_FACTOR_RECOVERY_CODES = 'two_factor_recovery_codes';

    public function __construct(
        private CsrfTokenManagerInterface $csrfTokenManager,
        private EntityManagerInterface $entityManager,
        private Security $security,
        private UrlGeneratorInterface $urlGenerator,
    ) {
    }

    public function __invoke(Request $request, string $twoFactorArea): RedirectResponse
    {
        $area = TwoFactorArea::from($twoFactorArea);
        $user = $this->requireTwoFactorUser();

        $this->assertValidCsrfToken((string) $request->request->get('_token'));

        $session = $request->getSession();

        $sessionKey = EnrollmentSessionKeys::recoveryCodes($user, $area->value);

        if (!$session->has($sessionKey)) {
            return new RedirectResponse($this->urlGenerator->generate($area->route('enroll')));
        }

        $user->acknowledgeTwoFactorRecoveryCodes();

        $this->entityManager->flush();

        $session->remove($sessionKey);
        $session->remove(SignInSessionKeys::key(SignInSessionKeys::TWO_FACTOR_LOGIN_PENDING, $user));
        $session->remove(SignInSessionKeys::key(SignInSessionKeys::TWO_FACTOR_EMAIL_CHALLENGE, $user));
        $session->set(SignInSessionKeys::key(SignInSessionKeys::TWO_FACTOR_VERIFIED, $user), 'totp');

        return new RedirectResponse($this->urlGenerator->generate($area->dashboardRoute()));
    }

    private function assertValidCsrfToken(string $token): void
    {
        $csrfToken = new CsrfToken(self::TWO_FACTOR_RECOVERY_CODES, $token);

        if (!$this->csrfTokenManager->isTokenValid($csrfToken)) {
            throw new AccessDeniedException('Invalid security token.');
        }
    }

    private function requireTwoFactorUser(): TwoFactorUserInterface
    {
        $user = $this->security->getUser();

        if (!$user instanceof TwoFactorUserInterface) {
            throw new AccessDeniedException();
        }

        return $user;
    }
}
