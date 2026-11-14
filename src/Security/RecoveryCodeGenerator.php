<?php

declare(strict_types=1);

namespace Tavy315\SyliusTwoFactorPlugin\Security;

class RecoveryCodeGenerator
{
    /** @return list<string> */
    public function generate(int $count = 10): array
    {
        $codes = [];

        for ($index = 0; $index < $count; ++$index) {
            $codes[] = strtoupper(
                substr(bin2hex(random_bytes(8)), 0, 8)
                . '-'
                . substr(bin2hex(random_bytes(8)), 0, 8),
            );
        }

        return $codes;
    }
}
