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
use Tavy315\SyliusTwoFactorPlugin\Entity\User\TwoFactorUserInterface;
use Tavy315\SyliusTwoFactorPlugin\Exception\InvalidEnrollmentCode;
use Tavy315\SyliusTwoFactorPlugin\Security\EnrollmentService;
use Tavy315\SyliusTwoFactorPlugin\Security\EnrollmentSessionKeys;

final readonly class ConfirmationController
{
    public function __construct(
        private CsrfTokenManagerInterface $csrfTokenManager,
        private EntityManagerInterface $entityManager,
        private EnrollmentService $enrollmentService,
        private Security $security,
        private UrlGeneratorInterface $urlGenerator,
    ) {
    }

    public function __invoke(Request $request, string $twoFactorArea): RedirectResponse
    {
        $area = TwoFactorArea::from($twoFactorArea);
        $user = $this->requireTwoFactorUser();

        $this->assertValidCsrfToken((string) $request->request->get('_token'));

        if ($user->hasCompletedTwoFactorEnrollment()) {
            return new RedirectResponse($this->urlGenerator->generate($area->dashboardRoute()));
        }

        $session = $request->getSession();

        try {
            $recoveryCodes = $this->enrollmentService->confirmAuthenticator(
                $user,
                (string) $session->get(EnrollmentSessionKeys::enrollmentSecret($user, $area->value), ''),
                (string) $request->request->get('code'),
            );
        } catch (InvalidEnrollmentCode) {
            $session->getFlashBag()->add('error', 'The code is invalid. Check your authenticator app and try again.');

            return new RedirectResponse($this->urlGenerator->generate($area->route('enroll')));
        }

        $this->entityManager->flush();

        $session->remove(EnrollmentSessionKeys::enrollmentSecret($user, $area->value));
        $session->set(EnrollmentSessionKeys::recoveryCodes($user, $area->value), $recoveryCodes);

        return new RedirectResponse($this->urlGenerator->generate($area->route('enroll')));
    }

    private function assertValidCsrfToken(string $token): void
    {
        $csrfToken = new CsrfToken(EnrollmentService::TWO_FACTOR_ENROLLMENT, $token);

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
