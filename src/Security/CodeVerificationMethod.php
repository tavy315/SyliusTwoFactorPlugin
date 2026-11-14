<?php

declare(strict_types=1);

namespace Tavy315\SyliusTwoFactorPlugin\Security;

enum CodeVerificationMethod
{
    case TOTP;
    case RECOVERY_CODE;
    case INVALID;
}
