# Sylius Two-Factor Plugin

Adds authenticator enrollment, single-use recovery codes, and optional email verification to Admin and Shop sign-in. This package targets Sylius 1.12 applications using Symfony 5.4 Security and Doctrine ORM annotations.

## Installation

1. Require `tavy315/sylius-two-factor-plugin` and register `Tavy315\SyliusTwoFactorPlugin\Tavy315SyliusTwoFactorPlugin` in `config/bundles.php`.
2. Implement `Tavy315\SyliusTwoFactorPlugin\Entity\User\TwoFactorUserInterface` and use `TwoFactorUserTrait` from the same namespace in both of the application's Doctrine user entities. The entities must implement their respective Sylius Admin or Shop user interfaces.
3. Enable DoctrineMigrationsBundle and run `php bin/console doctrine:migrations:migrate` after the Sylius Core migrations. The bundled migration targets the standard Admin and Shop user tables on MySQL or MariaDB. If your app already contains `DoctrineMigrations\Version20260921120000`, remove that local file when upgrading to the bundled version and keep its migration history. For custom user tables, adapt the migration to your schema before running it.
4. Import the routes in `config/routes/two_factor.yaml`.

   ```yaml
   tavy315_sylius_two_factor:
       resource: '@Tavy315SyliusTwoFactorPlugin/Resources/config/routing.yaml'
   ```

5. Protect the imported paths with the corresponding Admin and Shop firewalls and roles. Place these rules before broader rules in `security.access_control`. The Admin regex must match the configured Admin path.

   ```yaml
   - { path: '%sylius.security.admin_regex%/two-factor(?:/.*)?$', roles: ROLE_ADMINISTRATION_ACCESS }
   - { path: '^/two-factor(?:/.*)?$', roles: ROLE_USER }
   ```

## Configuration

- `TWO_FACTOR_TOTP_ENABLED=1` enables authenticator enrollment and verification.
- `TWO_FACTOR_ENCRYPTION_KEY` is a base64-encoded, 32-byte secret. Keep it stable across deployments and available to every application instance.
- `TWO_FACTOR_EMAIL_ENABLED=1` enables verification by email. Configure Symfony Mailer and set `TWO_FACTOR_EMAIL_SENDER` to a valid sender. Prevent unverified email changes in the host application before enabling this method.
- Override the Symfony parameter `tavy315_sylius_two_factor.issuer` to customize the authenticator label. It defaults to `Sylius`.
- Override templates under `templates/bundles/Tavy315SyliusTwoFactorPlugin/` to apply storefront branding.

Both verification methods are disabled by default.
