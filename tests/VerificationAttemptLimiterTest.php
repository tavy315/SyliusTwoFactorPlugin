<?php

declare(strict_types=1);

namespace Tavy315\SyliusTwoFactorPlugin\Tests;

use PHPUnit\Framework\TestCase;
use Symfony\Component\RateLimiter\RateLimiterFactory;
use Symfony\Component\RateLimiter\Storage\InMemoryStorage;
use Tavy315\SyliusTwoFactorPlugin\Security\VerificationAttemptLimiter;
use Tavy315\SyliusTwoFactorPlugin\Tests\Fixture\AdminUser;

final class VerificationAttemptLimiterTest extends TestCase
{
    public function testItLimitsAttemptsForOneUserAcrossDifferentIpAddresses(): void
    {
        $limiter = new VerificationAttemptLimiter(
            $this->factory('user', 5),
            $this->factory('ip', 20),
        );
        $user = $this->user('admin@example.com');

        for ($attempt = 1; $attempt <= 5; ++$attempt) {
            self::assertTrue($limiter->consume($user, '192.0.2.' . $attempt));
        }

        self::assertFalse($limiter->consume($user, '198.51.100.1'));
    }

    public function testItLimitsAttemptsFromOneIpAcrossDifferentUsers(): void
    {
        $limiter = new VerificationAttemptLimiter(
            $this->factory('user', 20),
            $this->factory('ip', 5),
        );

        for ($attempt = 1; $attempt <= 5; ++$attempt) {
            self::assertTrue($limiter->consume($this->user('admin' . $attempt . '@example.com'), '192.0.2.1'));
        }

        self::assertFalse($limiter->consume($this->user('blocked@example.com'), '192.0.2.1'));
    }

    private function factory(string $id, int $limit): RateLimiterFactory
    {
        return new RateLimiterFactory([
            'id' => $id,
            'policy' => 'fixed_window',
            'limit' => $limit,
            'interval' => '15 minutes',
        ], new InMemoryStorage());
    }

    private function user(string $email): AdminUser
    {
        $user = new AdminUser();
        $user->setEmail($email);

        return $user;
    }
}
