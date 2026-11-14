<?php

declare(strict_types=1);

namespace Tavy315\SyliusTwoFactorPlugin\Controller;

use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Mailer\Exception\TransportExceptionInterface;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Security\Core\Exception\AccessDeniedException;
use Symfony\Component\Security\Core\Security;
use Symfony\Component\Security\Csrf\CsrfToken;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;
use Tavy315\SyliusTwoFactorPlugin\Exception\InvalidTwoFactorCode;
use Tavy315\SyliusTwoFactorPlugin\Security\EmailChallenge;
use Tavy315\SyliusTwoFactorPlugin\Security\SignInSessionKeys;
use Tavy315\SyliusTwoFactorPlugin\Security\TwoFactorMethods;
use Tavy315\SyliusTwoFactorPlugin\Security\VerificationAttemptLimiter;
use Tavy315\SyliusTwoFactorPlugin\Security\VerificationService;
use Twig\Environment;

final readonly class VerificationController
{
    public const TWO_FACTOR_VERIFICATION = 'two_factor_verification';

    public function __construct(
        private CsrfTokenManagerInterface $csrfTokenManager,
        private Security $security,
        private Environment $twig,
        private UrlGeneratorInterface $urlGenerator,
        private VerificationAttemptLimiter $verificationAttemptLimiter,
        private VerificationService $verificationService,
        private TwoFactorMethods $methods,
        private EmailChallenge $emailChallenge,
    ) {
    }

    public function __invoke(Request $request, string $twoFactorArea): Response
    {
        $area = TwoFactorArea::from($twoFactorArea);
        $user = $this->security->getUser();
        if (!$area->acceptsVerificationUser($user)) {
            throw new AccessDeniedException();
        }

        $session = $request->getSession();
        $pendingKey = SignInSessionKeys::key(SignInSessionKeys::TWO_FACTOR_LOGIN_PENDING, $user);
        $verifiedKey = SignInSessionKeys::key(SignInSessionKeys::TWO_FACTOR_VERIFIED, $user);
        $challengeKey = SignInSessionKeys::key(SignInSessionKeys::TWO_FACTOR_EMAIL_CHALLENGE, $user);
        $totp = $this->methods->totp && $user->hasCompletedTwoFactorEnrollment();
        $email = $this->methods->emailAddress($user);

        if ((!$this->methods->email && !$totp) || $this->methods->isSatisfied($user, $session)) {
            throw new AccessDeniedException();
        }

        if (!$request->isMethod('POST')) {
            return new Response(
                content: $this->twig->render(
                    $area->template('verification'),
                    [
                        'totp'      => $totp,
                        'canEnroll' => $this->methods->totp && !$totp,
                        'email'     => $email !== null,
                        'emailSent' => $email !== null && $session->has($challengeKey),
                    ],
                ),
                headers: ['Cache-Control' => 'no-store'],
            );
        }

        $this->assertValidCsrfToken((string) $request->request->get('_token'));

        $method = $request->request->get('method', 'totp');

        if ($method === 'send_email' && $email !== null) {
            if (!$this->verificationAttemptLimiter->consume($user, $request->getClientIp(), 'email_send')) {
                $session->getFlashBag()->add('error', 'Too many code requests. Please try again later.');
            } else {
                try {
                    $this->emailChallenge->send($session, $challengeKey, $email);
                } catch (TransportExceptionInterface) {
                    $session->getFlashBag()->add('error', 'The sign-in email could not be sent. Please try again.');
                }
            }

            return new RedirectResponse($this->urlGenerator->generate($area->route('verify')));
        }

        try {
            $code = (string) $request->request->get('code');
            if ($method === 'email' && $email !== null) {
                if (!$this->verificationAttemptLimiter->consume($user, $request->getClientIp(), 'email_verify')) {
                    $session->getFlashBag()->add('error', 'Too many verification attempts. Please try again later.');

                    return new RedirectResponse($this->urlGenerator->generate($area->route('verify')));
                }

                $this->emailChallenge->verify($session, $challengeKey, $email, $code);
            } elseif ($method === 'totp' && $totp) {
                $this->verificationService->verifyOrFail($user, $code);
            } else {
                throw new AccessDeniedException();
            }
        } catch (InvalidTwoFactorCode) {
            $limited = $method === 'totp' && !$this->verificationAttemptLimiter->consume($user, $request->getClientIp());
            $session->getFlashBag()->add('error', $limited
                ? 'Too many verification attempts. Please try again later.'
                : 'The code is invalid or has expired. Please try again.');

            return new RedirectResponse($this->urlGenerator->generate($area->route('verify')));
        }

        $session->set($verifiedKey, $method);
        $session->remove($pendingKey);
        $session->remove($challengeKey);
        $target = $session->remove(SignInSessionKeys::key(SignInSessionKeys::TWO_FACTOR_LOGIN_TARGET, $user));

        return $this->isValidTarget($target)
            ? new RedirectResponse($target)
            : new RedirectResponse($this->urlGenerator->generate($area->dashboardRoute()));
    }

    private function assertValidCsrfToken(string $token): void
    {
        $csrfToken = new CsrfToken(self::TWO_FACTOR_VERIFICATION, $token);

        if (!$this->csrfTokenManager->isTokenValid($csrfToken)) {
            throw new AccessDeniedException('Invalid security token.');
        }
    }

    private function isValidTarget(mixed $target): bool
    {
        return \is_string($target)
            && str_starts_with($target, '/')
            && !str_starts_with($target, '//')
            && !str_contains($target, '\\')
            && !preg_match('#^/_(?:wdt|profiler)(?:/|\?|$)#', $target);
    }
}
