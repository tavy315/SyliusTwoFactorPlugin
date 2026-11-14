<?php

declare(strict_types=1);

namespace Tavy315\SyliusTwoFactorPlugin\Controller;

use Sylius\Component\Core\Model\AdminUserInterface;
use Sylius\Component\Core\Model\ShopUserInterface;
use Tavy315\SyliusTwoFactorPlugin\Entity\User\TwoFactorUserInterface;

enum TwoFactorArea: string
{
    case Admin = 'admin';
    case Shop = 'shop';

    public function route(string $action): string
    {
        return \sprintf('app_%s_two_factor_%s', $this->value, $action);
    }

    public function template(string $page): string
    {
        return \sprintf('@Tavy315SyliusTwoFactorPlugin/%s/%s.html.twig', $this->value, $page);
    }

    public function dashboardRoute(): string
    {
        return match ($this) {
            self::Admin => 'sylius_admin_dashboard',
            self::Shop  => 'sylius_shop_account_dashboard',
        };
    }

    /** @phpstan-assert-if-true (AdminUserInterface|ShopUserInterface)&TwoFactorUserInterface $user */
    public function acceptsVerificationUser(mixed $user): bool
    {
        return $user instanceof TwoFactorUserInterface && match ($this) {
            self::Admin => $user instanceof AdminUserInterface,
            self::Shop  => $user instanceof ShopUserInterface,
        };
    }
}
