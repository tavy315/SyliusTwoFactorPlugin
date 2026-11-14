<?php

declare(strict_types=1);

namespace Tavy315\SyliusTwoFactorPlugin\Tests\Fixture;

use Sylius\Component\Core\Model\ShopUserInterface as BaseShopUserInterface;
use Tavy315\SyliusTwoFactorPlugin\Entity\User\TwoFactorUserInterface;

interface ShopUserInterface extends BaseShopUserInterface, TwoFactorUserInterface
{
}
