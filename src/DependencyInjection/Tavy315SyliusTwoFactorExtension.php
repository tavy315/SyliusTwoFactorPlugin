<?php

declare(strict_types=1);

namespace Tavy315\SyliusTwoFactorPlugin\DependencyInjection;

use DoctrineMigrations\Version20260921120000;
use DoctrineMigrations\Version20261115120000;
use Symfony\Component\Config\FileLocator;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Extension\Extension;
use Symfony\Component\DependencyInjection\Extension\PrependExtensionInterface;
use Symfony\Component\DependencyInjection\Loader\YamlFileLoader;
use Symfony\Component\Yaml\Yaml;

final class Tavy315SyliusTwoFactorExtension extends Extension implements PrependExtensionInterface
{
    public function prepend(ContainerBuilder $container): void
    {
        $file = __DIR__ . '/../Resources/config/rate_limiter.yaml';
        $container->fileExists($file);
        $container->prependExtensionConfig('framework', Yaml::parseFile($file)['framework']);

        if (!$container->hasExtension('doctrine_migrations')) {
            return;
        }

        // Keep the original class name so existing migration records still match.
        $container->prependExtensionConfig('doctrine_migrations', [
            'migrations' => [Version20260921120000::class, Version20261115120000::class],
        ]);

        if ($container->hasExtension('sylius_labs_doctrine_migrations_extra')) {
            $container->prependExtensionConfig('sylius_labs_doctrine_migrations_extra', [
                'migrations' => [
                    'DoctrineMigrations' => ['Sylius\Bundle\CoreBundle\Migrations'],
                ],
            ]);
        }
    }

    public function load(array $configs, ContainerBuilder $container): void
    {
        $loader = new YamlFileLoader($container, new FileLocator(__DIR__ . '/../Resources/config'));
        $loader->load('services.yaml');
    }
}
