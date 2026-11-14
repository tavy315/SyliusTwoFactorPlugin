<?php

declare(strict_types=1);

namespace Tavy315\SyliusTwoFactorPlugin\EventSubscriber;

use Sylius\Component\Core\Model\AdminUserInterface;
use Symfony\Bundle\SecurityBundle\Security\FirewallMap;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\KernelEvents;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Security\Core\Security;
use Tavy315\SyliusTwoFactorPlugin\Entity\User\TwoFactorUserInterface;
use Tavy315\SyliusTwoFactorPlugin\Security\SignInSessionKeys;
use Tavy315\SyliusTwoFactorPlugin\Security\TwoFactorMethods;

final readonly class EnrollmentGateSubscriber implements EventSubscriberInterface
{
    public function __construct(
        private Security $security,
        private UrlGeneratorInterface $urlGenerator,
        private TwoFactorMethods $methods = new TwoFactorMethods(),
        private ?FirewallMap $firewallMap = null,
    ) {
    }

    public static function getSubscribedEvents(): array
    {
        return [KernelEvents::REQUEST => ['requireEnrollment', 0]];
    }

    public function requireEnrollment(RequestEvent $event): void
    {
        if (!$event->isMainRequest() || $event->hasResponse()) {
            return;
        }

        $request = $event->getRequest();
        if ($this->isProfilerRequest($request) || $this->firewallMap?->getFirewallConfig($request)?->isStateless()) {
            return;
        }

        $user = $this->security->getUser();

        if (!$user instanceof TwoFactorUserInterface) {
            return;
        }

        $scope = $user instanceof AdminUserInterface ? 'admin' : 'shop';
        $prefix = 'app_' . $scope . '_two_factor_';
        $route = $request->attributes->get('_route');
        if (!$this->methods->isEnabled()) {
            if (\is_string($route) && str_starts_with($route, $prefix)) {
                $dashboard = $scope === 'admin' ? 'sylius_admin_dashboard' : 'sylius_shop_account_dashboard';
                $event->setResponse(new RedirectResponse($this->urlGenerator->generate($dashboard), 303));
            }

            return;
        }

        if ($route === 'sylius_' . $scope . '_logout' || $route === $prefix . 'verify') {
            return;
        }

        $enrollmentRoute = \in_array($route, [
            $prefix . 'enroll',
            $prefix . 'confirm',
            $prefix . 'acknowledge',
        ], true);

        if ($enrollmentRoute && $this->methods->totp) {
            return;
        }

        if (!$enrollmentRoute && $this->methods->isSatisfied($user, $request->getSession())) {
            return;
        }

        $route = $prefix . 'enroll';
        if (!$this->methods->totp || $user->hasCompletedTwoFactorEnrollment() || $this->methods->emailAddress($user) !== null) {
            $route = $prefix . 'verify';

            if (!$enrollmentRoute) {
                $this->storeTargetPath($request, $user);
            }
        }

        if ($request->isXmlHttpRequest()) {
            $event->setResponse(new JsonResponse(['two_factor_enrollment_required' => true], 403));

            return;
        }

        $event->setResponse(new RedirectResponse($this->urlGenerator->generate($route)));
    }

    private function isProfilerRequest(Request $request): bool
    {
        return (bool) preg_match('#^/_(?:wdt|profiler)(?:/|$)#', $request->getPathInfo());
    }

    private function storeTargetPath(Request $request, TwoFactorUserInterface $user): void
    {
        if (
            !$request->isMethod('GET')
            || $request->isXmlHttpRequest()
            || $this->isProfilerRequest($request)
        ) {
            return;
        }

        $request->getSession()->set(SignInSessionKeys::key(SignInSessionKeys::TWO_FACTOR_LOGIN_TARGET, $user), $request->getRequestUri());
    }
}
