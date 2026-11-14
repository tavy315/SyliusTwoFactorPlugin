<?php

declare(strict_types=1);

namespace Tavy315\SyliusTwoFactorPlugin\Tests;

use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\HttpFoundation\Session\Storage\MockArraySessionStorage;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\HttpKernelInterface;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Security\Core\Security;
use Tavy315\SyliusTwoFactorPlugin\EventSubscriber\EnrollmentGateSubscriber;
use Tavy315\SyliusTwoFactorPlugin\Security\SignInSessionKeys;
use Tavy315\SyliusTwoFactorPlugin\Security\TwoFactorMethods;
use Tavy315\SyliusTwoFactorPlugin\Tests\Fixture\ShopUserInterface;

final class TwoFactorEnrollmentGateTest extends TestCase
{
    public function testBackgroundRequestsDoNotReplaceLoginDestination(): void
    {
        $user = $this->createMock(ShopUserInterface::class);
        $user->method('hasCompletedTwoFactorEnrollment')->willReturn(true);
        $security = $this->createMock(Security::class);
        $security->method('getUser')->willReturn($user);
        $router = $this->createMock(UrlGeneratorInterface::class);
        $router->method('generate')->willReturn('/two-factor/verify');
        $subscriber = new EnrollmentGateSubscriber($security, $router);
        $session = new Session(new MockArraySessionStorage());
        $session->set(SignInSessionKeys::TWO_FACTOR_LOGIN_PENDING, true);

        foreach ([
            ['/account', false],
            ['/ajax/cart', true],
        ] as [$path, $ajax]) {
            $request = Request::create($path);
            $request->setSession($session);
            if ($ajax) {
                $request->headers->set('X-Requested-With', 'XMLHttpRequest');
            }
            $event = new RequestEvent($this->createMock(HttpKernelInterface::class), $request, HttpKernelInterface::MAIN_REQUEST);
            $subscriber->requireEnrollment($event);

            self::assertSame('/account', $session->get(SignInSessionKeys::key(SignInSessionKeys::TWO_FACTOR_LOGIN_TARGET, $user)), $path);
            self::assertTrue($event->hasResponse(), 'Pending verification must still block protected requests.');
        }
    }

    public function testEmailMethodUsesTheAccountAddressWithoutAVerificationTimestamp(): void
    {
        $user = $this->createMock(ShopUserInterface::class);
        $user->method('getEmail')->willReturn('customer@example.com');
        $user->method('isVerified')->willReturn(false);

        self::assertSame('customer@example.com', (new TwoFactorMethods(false, true))->emailAddress($user));
        self::assertNull((new TwoFactorMethods(true, false))->emailAddress($user));
    }

    public function testDisabledMethodsAllowAccountAccessAndRedirectOldChallenges(): void
    {
        $user = $this->createMock(ShopUserInterface::class);
        $security = $this->createMock(Security::class);
        $security->method('getUser')->willReturn($user);
        $router = $this->createMock(UrlGeneratorInterface::class);
        $router->expects(self::once())->method('generate')
            ->with('sylius_shop_account_dashboard')->willReturn('/account');
        $subscriber = new EnrollmentGateSubscriber($security, $router, new TwoFactorMethods(false, false));
        $kernel = $this->createMock(HttpKernelInterface::class);
        $session = new Session(new MockArraySessionStorage());
        $session->set(SignInSessionKeys::key(SignInSessionKeys::TWO_FACTOR_LOGIN_PENDING, $user), true);

        $request = Request::create('/account');
        $request->setSession($session);
        $event = new RequestEvent($kernel, $request, HttpKernelInterface::MAIN_REQUEST);
        $subscriber->requireEnrollment($event);
        self::assertFalse($event->hasResponse());

        $request = Request::create('/two-factor/verify');
        $request->attributes->set('_route', 'app_shop_two_factor_verify');
        $request->setSession($session);
        $event = new RequestEvent($kernel, $request, HttpKernelInterface::MAIN_REQUEST);
        $subscriber->requireEnrollment($event);
        self::assertSame('/account', $event->getResponse()->headers->get('Location'));
    }

    public function testEmailOnlyRequiresVerificationEvenForAnEnrolledAccount(): void
    {
        $user = $this->createMock(ShopUserInterface::class);
        $user->method('hasCompletedTwoFactorEnrollment')->willReturn(true);
        $security = $this->createMock(Security::class);
        $security->method('getUser')->willReturn($user);
        $router = $this->createMock(UrlGeneratorInterface::class);
        $router->expects(self::once())->method('generate')
            ->with('app_shop_two_factor_verify')->willReturn('/two-factor/verify');
        $subscriber = new EnrollmentGateSubscriber($security, $router, new TwoFactorMethods(false, true));
        $session = new Session(new MockArraySessionStorage());
        $request = Request::create('/account');
        $request->setSession($session);
        $kernel = $this->createMock(HttpKernelInterface::class);
        $verifiedKey = SignInSessionKeys::key(SignInSessionKeys::TWO_FACTOR_VERIFIED, $user);

        $session->set($verifiedKey, 'totp');
        $event = new RequestEvent($kernel, $request, HttpKernelInterface::MAIN_REQUEST);
        $subscriber->requireEnrollment($event);
        self::assertTrue($event->hasResponse());

        $session->set($verifiedKey, 'email');
        $event = new RequestEvent($kernel, $request, HttpKernelInterface::MAIN_REQUEST);
        $subscriber->requireEnrollment($event);
        self::assertFalse($event->hasResponse());
    }

    public function testProfilerRequestsBypassTheEnrollmentGate(): void
    {
        $user = $this->createMock(ShopUserInterface::class);
        $user->method('hasCompletedTwoFactorEnrollment')->willReturn(true);
        $security = $this->createMock(Security::class);
        $security->method('getUser')->willReturn($user);
        $subscriber = new EnrollmentGateSubscriber($security, $this->createMock(UrlGeneratorInterface::class));
        $session = new Session(new MockArraySessionStorage());
        $session->set(SignInSessionKeys::TWO_FACTOR_LOGIN_PENDING, true);

        foreach (['/_wdt/f78206', '/_profiler/f78206'] as $path) {
            $request = Request::create($path);
            $request->setSession($session);
            $request->headers->set('X-Requested-With', 'XMLHttpRequest');
            $event = new RequestEvent($this->createMock(HttpKernelInterface::class), $request, HttpKernelInterface::MAIN_REQUEST);

            $subscriber->requireEnrollment($event);

            self::assertFalse($event->hasResponse(), $path);
        }
    }
}
