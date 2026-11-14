<?php

declare(strict_types=1);

namespace Tavy315\SyliusTwoFactorPlugin\Tests;

use PHPUnit\Framework\TestCase;
use Tavy315\SyliusTwoFactorPlugin\Security\RecoveryCodeGenerator;

final class RecoveryCodeGeneratorTest extends TestCase
{
    public function testItGeneratesTheRequestedNumberOfUniqueFormattedCodes(): void
    {
        $codes = (new RecoveryCodeGenerator())->generate(4);

        self::assertCount(4, $codes);
        self::assertCount(4, array_unique($codes));

        foreach ($codes as $code) {
            self::assertMatchesRegularExpression('/^[A-F0-9]{8}-[A-F0-9]{8}$/', $code);
        }
    }
}
