<?php

declare(strict_types=1);

namespace DoctrineMigrations;

use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\AbstractMigration;

final class Version20260921120000 extends AbstractMigration
{
    public function getDescription(): string
    {
        return 'Stores encrypted TOTP secrets and recovery-code state for shop and admin users.';
    }

    public function up(Schema $schema): void
    {
        foreach (['sylius_admin_user', 'sylius_shop_user'] as $table) {
            $this->addSql(sprintf('ALTER TABLE %s ADD two_factor_totp_secret LONGTEXT DEFAULT NULL, ADD two_factor_recovery_codes JSON DEFAULT NULL, ADD two_factor_enrolled_at DATETIME DEFAULT NULL, ADD two_factor_acknowledged_at DATETIME DEFAULT NULL', $table));
        }
    }

    public function down(Schema $schema): void
    {
        foreach (['sylius_admin_user', 'sylius_shop_user'] as $table) {
            $this->addSql(sprintf('ALTER TABLE %s DROP two_factor_totp_secret, DROP two_factor_recovery_codes, DROP two_factor_enrolled_at, DROP two_factor_acknowledged_at', $table));
        }
    }
}
