<?php

declare(strict_types=1);

namespace Tavy315\SyliusTwoFactorPlugin\EventSubscriber;

use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\Security\Http\Event\LogoutEvent;
use Tavy315\SyliusTwoFactorPlugin\Security\EnrollmentSessionKeys;
use Tavy315\SyliusTwoFactorPlugin\Security\SignInSessionKeys;
use Tavy315\SyliusTwoFactorPlugin\Security\TwoFactorUserInterface;

final class LogoutSubscriber implements EventSubscriberInterface
{
    public static function getSubscribedEvents(): array
    {
        return [LogoutEvent::class => 'clearTwoFactorSessionState'];
    }

    public function clearTwoFactorSessionState(LogoutEvent $event): void
    {
        $session = $event->getRequest()->getSession();
        $user = $event->getToken()?->getUser();
        if (!$user instanceof TwoFactorUserInterface) {
            return;
        }

        foreach ([SignInSessionKeys::TWO_FACTOR_LOGIN_PENDING, SignInSessionKeys::TWO_FACTOR_LOGIN_TARGET, SignInSessionKeys::TWO_FACTOR_VERIFIED, SignInSessionKeys::TWO_FACTOR_EMAIL_CHALLENGE] as $key) {
            $session->remove(SignInSessionKeys::key($key, $user));
        }

        foreach (['admin', 'shop'] as $scope) {
            $session->remove(EnrollmentSessionKeys::enrollmentSecret($user, $scope));
            $session->remove(EnrollmentSessionKeys::recoveryCodes($user, $scope));
        }
    }
}
