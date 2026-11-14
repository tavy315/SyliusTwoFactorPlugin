<?php

declare(strict_types=1);

namespace Tavy315\SyliusTwoFactorPlugin\EventSubscriber;

use Sylius\Bundle\UserBundle\Event\UserEvent;
use Sylius\Bundle\UserBundle\UserEvents;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\HttpFoundation\Session\SessionInterface;
use Symfony\Component\Security\Http\Event\InteractiveLoginEvent;
use Symfony\Component\Security\Http\SecurityEvents;
use Tavy315\SyliusTwoFactorPlugin\Security\SignInSessionKeys;
use Tavy315\SyliusTwoFactorPlugin\Security\TwoFactorUserInterface;

class LoginPendingSubscriber implements EventSubscriberInterface
{
    public function __construct(private readonly RequestStack $requestStack)
    {
    }

    public static function getSubscribedEvents(): array
    {
        return [
            SecurityEvents::INTERACTIVE_LOGIN   => ['markInteractiveLoginPending', 100],
            UserEvents::SECURITY_IMPLICIT_LOGIN => ['markImplicitLoginPending', 100],
        ];
    }

    public function markInteractiveLoginPending(InteractiveLoginEvent $event): void
    {
        $user = $event->getAuthenticationToken()->getUser();
        $this->markPending($user, $event->getRequest()->getSession());
    }

    public function markImplicitLoginPending(UserEvent $event): void
    {
        $request = $this->requestStack->getCurrentRequest();
        if ($request === null || !$request->hasSession()) {
            return;
        }

        $this->markPending($event->getUser(), $request->getSession());
    }

    private function markPending(mixed $user, SessionInterface $session): void
    {
        if (!$user instanceof TwoFactorUserInterface) {
            return;
        }

        $session->remove(SignInSessionKeys::key(SignInSessionKeys::TWO_FACTOR_VERIFIED, $user));
        $session->remove(SignInSessionKeys::key(SignInSessionKeys::TWO_FACTOR_EMAIL_CHALLENGE, $user));
        $session->remove(SignInSessionKeys::key(SignInSessionKeys::TWO_FACTOR_LOGIN_TARGET, $user));
        $session->set(SignInSessionKeys::key(SignInSessionKeys::TWO_FACTOR_LOGIN_PENDING, $user), true);
    }
}
