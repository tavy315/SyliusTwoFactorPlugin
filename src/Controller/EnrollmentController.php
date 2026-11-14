<?php

declare(strict_types=1);

namespace Tavy315\SyliusTwoFactorPlugin\Controller;

use BaconQrCode\Renderer\ImageRenderer;
use BaconQrCode\Renderer\Image\SvgImageBackEnd;
use BaconQrCode\Renderer\RendererStyle\RendererStyle;
use BaconQrCode\Writer;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Security\Core\Exception\AccessDeniedException;
use Symfony\Component\Security\Core\Security;
use Tavy315\SyliusTwoFactorPlugin\Security\EnrollmentService;
use Tavy315\SyliusTwoFactorPlugin\Security\EnrollmentSessionKeys;
use Tavy315\SyliusTwoFactorPlugin\Security\TwoFactorUserInterface;
use Twig\Environment;

final readonly class EnrollmentController
{
    public function __construct(
        private EnrollmentService $enrollmentService,
        private EntityManagerInterface $entityManager,
        private Security $security,
        private Environment $twig,
        private UrlGeneratorInterface $urlGenerator,
    ) {
    }

    public function __invoke(Request $request, string $twoFactorArea): Response
    {
        $area = TwoFactorArea::from($twoFactorArea);
        $user = $this->requireTwoFactorUser();

        if ($user->hasCompletedTwoFactorEnrollment()) {
            return new RedirectResponse($this->urlGenerator->generate($area->dashboardRoute()));
        }

        return $user->getTwoFactorTotpSecret() !== null
            ? $this->showRecoveryCodes($request, $user, $area)
            : $this->showEnrollment($request, $user, $area);
    }

    private function pendingSecret(Request $request, TwoFactorUserInterface $user, TwoFactorArea $area): string
    {
        $sessionKey = EnrollmentSessionKeys::enrollmentSecret($user, $area->value);

        $secret = (string) $request->getSession()->get($sessionKey, '');

        if ($secret !== '') {
            return $secret;
        }

        $secret = $this->enrollmentService->generateSecret();
        $request->getSession()->set($sessionKey, $secret);

        return $secret;
    }

    private function requireTwoFactorUser(): TwoFactorUserInterface
    {
        $user = $this->security->getUser();

        if (!$user instanceof TwoFactorUserInterface) {
            throw new AccessDeniedException();
        }

        return $user;
    }

    private function showEnrollment(Request $request, TwoFactorUserInterface $user, TwoFactorArea $area): Response
    {
        $secret = $this->pendingSecret($request, $user, $area);

        $qrCodeWriter = new Writer(new ImageRenderer(new RendererStyle(220), new SvgImageBackEnd()));

        return new Response(
            $this->twig->render($area->template('enrollment'), [
                'manualKey' => $secret,
                'qrCodeSvg' => $qrCodeWriter->writeString($this->enrollmentService->provisioningUri($user, $secret)),
            ]),
        );
    }

    private function showRecoveryCodes(Request $request, TwoFactorUserInterface $user, TwoFactorArea $area): Response
    {
        $recoveryCodes = $request->getSession()->get(EnrollmentSessionKeys::recoveryCodes($user, $area->value));

        if (!\is_array($recoveryCodes)) {
            $this->restartIncompleteEnrollment($request, $user, $area);

            return $this->showEnrollment($request, $user, $area);
        }

        return new Response(
            $this->twig->render($area->template('recovery-codes'), ['recoveryCodes' => $recoveryCodes]),
            Response::HTTP_OK,
            ['Cache-Control' => 'no-store, private'],
        );
    }

    private function restartIncompleteEnrollment(Request $request, TwoFactorUserInterface $user, TwoFactorArea $area): void
    {
        $session = $request->getSession();
        $session->remove(EnrollmentSessionKeys::enrollmentSecret($user, $area->value));
        $session->remove(EnrollmentSessionKeys::recoveryCodes($user, $area->value));

        $user->restartIncompleteTwoFactorEnrollment();
        $this->entityManager->flush();
    }
}
