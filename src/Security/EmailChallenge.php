<?php

declare(strict_types=1);

namespace Tavy315\SyliusTwoFactorPlugin\Security;

use Symfony\Component\HttpFoundation\Session\SessionInterface;
use Symfony\Component\Mailer\Transport\TransportInterface;
use Symfony\Component\Mime\Email;
use Tavy315\SyliusTwoFactorPlugin\Exception\InvalidTwoFactorCode;

final readonly class EmailChallenge
{
    public function __construct(
        private TransportInterface $transport,
        private string $senderAddress,
        private string $secret,
    ) {
    }

    public function send(SessionInterface $session, string $key, string $address): void
    {
        $session->start();
        $code = sprintf('%06d', random_int(0, 999999));
        $this->transport->send((new Email())
            ->from($this->senderAddress)
            ->to($address)
            ->subject('Your sign-in code')
            ->text(sprintf('Your sign-in code is %s. It expires in 5 minutes.', $code)));

        $session->set($key, [
            'expires' => time() + 300,
            'digest' => $this->digest($session, $key, $address, $code),
        ]);
    }

    public function verify(SessionInterface $session, string $key, string $address, string $code): void
    {
        $challenge = $session->get($key);
        if (
            $challenge === null
            || $challenge['expires'] <= time()
            || !preg_match('/^[0-9]{6}$/D', $code)
            || !hash_equals($challenge['digest'], $this->digest($session, $key, $address, $code))
        ) {
            throw new InvalidTwoFactorCode();
        }

        $session->remove($key);
    }

    private function digest(SessionInterface $session, string $key, string $address, string $code): string
    {
        return hash_hmac('sha256', implode("\0", [$session->getId(), $key, $address, $code]), $this->secret);
    }
}
