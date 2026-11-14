<?php

declare(strict_types=1);

$storeAutoload = getenv('SYLIUS_TWO_FACTOR_TEST_AUTOLOAD');
$loader = require $storeAutoload ?: dirname(__DIR__) . '/vendor/autoload.php';

if ($storeAutoload) {
    // Composer loads autoload-dev entries only for the root package.
    $loader->addPsr4('Tavy315\\SyliusTwoFactorPlugin\\Tests\\', __DIR__);
}
