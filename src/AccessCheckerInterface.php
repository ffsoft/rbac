<?php

declare(strict_types=1);

namespace ffsoft\Access;

/**
 * The interface defines checking if  certain user has certain permission. Optional parameters could be passed
 * for fine grained access checks.
 */
interface AccessCheckerInterface
{
    /**
     * Checks if the user with the ID given has the specified permission.
     *
     * @param mixed  $userId         the user ID representing the unique identifier of a user.
     * @param string $application
     * @param string $permissionName the name of the permission to be checked against.
     * @param array  $parameters     name-value pairs that will used to determine if access is granted.
     *
     * @return bool whether the user has the specified permission.
     */
    public function userHasPermission($userId, string $application, string $permissionName, array $parameters = []): bool;
}
