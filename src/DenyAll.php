<?php

declare(strict_types=1);

namespace ffsoft\Rbac;

use ffsoft\Access\AccessCheckerInterface;

/**
 * Deny all access.
 */
class DenyAll implements AccessCheckerInterface
{
    public function userHasPermission($userId, string $application, string $permissionName, array $parameters = []): bool
    {
        return false;
    }
}
