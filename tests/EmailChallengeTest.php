<?php

declare(strict_types=1);

namespace Tavy315\SyliusTwoFactorPlugin\Tests;

use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\HttpFoundation\Session\Storage\MockArraySessionStorage;
use Symfony\Component\Mailer\Transport\TransportInterface;
use Symfony\Component\Mime\Email;
use Tavy315\SyliusTwoFactorPlugin\Exception\InvalidTwoFactorCode;
use Tavy315\SyliusTwoFactorPlugin\Security\EmailChallenge;

final class EmailChallengeTest extends TestCase
{
    public function testCodeIsBoundToTheAddressAndCanOnlyBeUsedOnce(): void
    {
        $session = new Session(new MockArraySessionStorage());
        $transport = $this->createMock(TransportInterface::class);
        $code = '';
        $transport->expects(self::once())->method('send')->willReturnCallback(
            static function (Email $email) use (&$code): null {
                self::assertSame('customer@example.com', $email->getTo()[0]->getAddress());
                self::assertSame(1, preg_match('/\b[0-9]{6}\b/', $email->getTextBody(), $matches));
                $code = $matches[0];

                return null;
            },
        );

        $challenge = new EmailChallenge($transport, 'store@example.com', 'test-secret');
        $challenge->send($session, 'challenge', 'customer@example.com');

        self::assertNotSame($code, $session->get('challenge')['digest']);
        try {
            $challenge->verify($session, 'challenge', 'other@example.com', $code);
            self::fail('A different email address must invalidate the challenge.');
        } catch (InvalidTwoFactorCode) {
            self::assertTrue($session->has('challenge'));
        }

        $challenge->verify($session, 'challenge', 'customer@example.com', $code);
        self::assertFalse($session->has('challenge'));

        $this->expectException(InvalidTwoFactorCode::class);
        $challenge->verify($session, 'challenge', 'customer@example.com', $code);
    }
}
