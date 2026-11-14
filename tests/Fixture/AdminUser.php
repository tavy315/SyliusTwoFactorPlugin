<?php

declare(strict_types=1);

namespace Tavy315\SyliusTwoFactorPlugin\Tests\Fixture;

use Sylius\Component\Core\Model\AdminUser as BaseAdminUser;
use Tavy315\SyliusTwoFactorPlugin\Entity\User\TwoFactorUserInterface;
use Tavy315\SyliusTwoFactorPlugin\Entity\User\TwoFactorUserTrait;

final class AdminUser extends BaseAdminUser implements TwoFactorUserInterface
{
    use TwoFactorUserTrait;
}
