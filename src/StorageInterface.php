<?php

declare(strict_types=1);

namespace ffsoft\Rbac;

/**
 * StorageInterface represents a storage for RBAC items used in {@see Manager}.
 *
 * @package ffsoft\Rbac
 */
interface StorageInterface
{
    /**
     * Removes all authorization data, including roles, permissions, rules, and assignments.
     *
     * @param string|null $application
     */
    public function clear(?string $application = null): void;

    /**
     * Returns all items in the system.
     *
     * @param string|null $application
     * @return Item[] All items in the system.
     */
    public function getItems(?string $application = null): array;

    /**
     * Returns the named item.
     *
     * @param string $application
     * @param string $name The item name.
     *
     * @return Item|null The item corresponding to the specified name. Null is returned if no such item.
     */
    public function getItemByName(string $application, string $name): ?Item;

    /**
     * Adds the item to RBAC system.
     * @param Item $item The item to add.
     */
    public function addItem(Item $item): void;

    /**
     * Updates the specified role, permission or rule in the system.
     * @param string $name The old name of the role, permission or rule.
     * @param Item $item Modified item.
     */
    public function updateItem(string $name, Item $item): void;

    /**
     * Removes a role, permission or rule from the RBAC system.
     * @param Item $item Item to remove.
     */
    public function removeItem(Item $item): void;

    /**
     * @return array
     */
    public function getChildren(): array;

    /**
     * Returns all roles in the system.
     * @return Role[] All roles in the system.
     */
    public function getRoles(): array;

    /**
     * Returns the named role.
     *
     * @param string $application
     * @param string $name The role name.
     *
     * @return Role|null The role corresponding to the specified name. Null is returned if no such role.
     */
    public function getRoleByName(string $application, string $name): ?Role;

    /**
     * Removes all roles.
     * All parent child relations will be adjusted accordingly.
     */
    public function clearRoles(): void;

    /**
     * Returns all permissions in the system.
     * @return Permission[] All permissions in the system.
     */
    public function getPermissions(): array;

    /**
     * Returns the named permission.
     *
     * @param string $application
     * @param string $name The permission name.
     *
     * @return Permission|null The permission corresponding to the specified name. Null is returned if no such permission.
     */
    public function getPermissionByName(string $application, string $name): ?Permission;

    /**
     * Removes all permissions.
     * All parent child relations will be adjusted accordingly.
     */
    public function clearPermissions(): void;

    /**
     * Returns the child permissions and/or roles.
     *
     * @param string $application
     * @param string $name The parent name.
     *
     * @return Item[] The child permissions and/or roles.
     */
    public function getChildrenByName(string $application, string $name): array;

    /**
     * Returns whether named parent has children.
     *
     * @param string $application
     * @param string $name The parent name.
     *
     * @return bool Whether named parent has children.
     */
    public function hasChildren(string $application, string $name): bool;

    /**
     * Adds an item as a child of another item.
     * @param Item $parent Parent to add child to.
     * @param Item $child Child to add.
     */
    public function addChild(Item $parent, Item $child): void;

    /**
     * Removes a child from its parent.
     * Note, the child item is not deleted. Only the parent-child relationship is removed.
     * @param Item $parent Parent to remove child from.
     * @param Item $child Child to remove.
     */
    public function removeChild(Item $parent, Item $child): void;

    /**
     * Removed all children form their parent.
     * Note, the children items are not deleted. Only the parent-child relationships are removed.
     * @param Item $parent Parent to remove children from.
     */
    public function removeChildren(Item $parent): void;

    /**
     * Returns all role assignment information.
     * @return Assignment[]
     */
    public function getAssignments(): array;

    /**
     * Returns all role assignment information for the specified user.
     *
     * @param string      $userId The user ID.
     * @param string|null $application
     *
     * @return Assignment[] The assignments. An empty array will be
     * returned if there is no role assigned to the user.
     */
    public function getUserAssignments(string $userId, ?string $application = null): array;

    /**
     * Returns role assignment for the specified item name that belongs to user with the specified ID.
     *
     * @param string $userId The user ID.
     * @param string $application
     * @param string $name   Role name.
     *
     * @return Assignment|null Assignment or null if there is no role assigned to the user.
     */
    public function getUserAssignmentByName(string $userId, string $application, string $name): ?Assignment;

    /**
     * Adds assignment of the role to the user with ID specified.
     * @param string $userId The user ID.
     * @param Item $item Role to assign.
     */
    public function addAssignment(string $userId, Item $item): void;

    /**
     * Returns whether there is assignment for a named role or permission.
     *
     * @param string $application
     * @param string $name Name of the role or the permission.
     *
     * @return bool Whether there is assignment.
     */
    public function assignmentExist(string $application, string $name): bool;

    /**
     * Removes assignment of a role to the user with ID specified.
     * @param string $userId The user ID.
     * @param Item $item Role to remove assignment to.
     */
    public function removeAssignment(string $userId, Item $item): void;

    /**
     * Removes all role assignments for a user with ID specified.
     *
     * @param string      $userId The user ID.
     * @param string|null $application
     */
    public function removeAllAssignments(string $userId, ?string $application = null): void;

    /**
     * Removes all role assignments.
     */
    public function clearAssignments(): void;

    /**
     * Returns all rules available in the system.
     * @return Rule[] The rules indexed by the rule names.
     */
    public function getRules(): array;

    /**
     * Returns the rule of the specified name.
     * @param string $name The rule name.
     * @return Rule|null The rule object, or null if the specified name does not correspond to a rule.
     */
    public function getRuleByName(string $name): ?Rule;

    /**
     * Removes the rule of the specified name from RBAC system.
     * @param string $name The rule name.
     */
    public function removeRule(string $name): void;

    /**
     * Adds the rule to RBAC system.
     * @param Rule $rule The rule to add.
     */
    public function addRule(Rule $rule): void;

    /**
     * Removes all rules.
     * All roles and permissions which have rules will be adjusted accordingly.
     */
    public function clearRules(): void;
}
