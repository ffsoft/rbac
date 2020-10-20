<?php

namespace Yiisoft\Rbac\Storages;

use Doctrine\ORM\EntityManagerInterface;
use ffsoft\Rbac\Assignment;
use ffsoft\Rbac\Item;
use ffsoft\Rbac\Permission;
use ffsoft\Rbac\Role;
use ffsoft\Rbac\Rule;
use ffsoft\Rbac\StorageInterface;

class DoctrineORMStorage implements StorageInterface
{

    protected EntityManagerInterface $em;



    public function __construct(EntityManagerInterface $em)
    {
        $this->em = $em;
        $items
    }

    /**
     * Removes all authorization data, including roles, permissions, rules, and assignments.
     */
    public function clear(): void
    {
        // TODO: Implement clear() method.
    }

    /**
     * Returns all items in the system.
     *
     * @return Item[] All items in the system.
     */
    public function getItems(): array
    {
        // TODO: Implement getItems() method.
    }

    /**
     * Returns the named item.
     *
     * @param string $name The item name.
     *
     * @return Item|null The item corresponding to the specified name. Null is returned if no such item.
     */
    public function getItemByName(string $name): ?Item
    {
        // TODO: Implement getItemByName() method.
    }

    /**
     * Adds the item to RBAC system.
     *
     * @param Item $item The item to add.
     */
    public function addItem(Item $item): void
    {
        // TODO: Implement addItem() method.
    }

    /**
     * Updates the specified role, permission or rule in the system.
     *
     * @param string $name The old name of the role, permission or rule.
     * @param Item   $item Modified item.
     */
    public function updateItem(string $name, Item $item): void
    {
        // TODO: Implement updateItem() method.
    }

    /**
     * Removes a role, permission or rule from the RBAC system.
     *
     * @param Item $item Item to remove.
     */
    public function removeItem(Item $item): void
    {
        // TODO: Implement removeItem() method.
    }

    /**
     * @return array
     */
    public function getChildren(): array
    {
        // TODO: Implement getChildren() method.
    }

    /**
     * Returns all roles in the system.
     *
     * @return Role[] All roles in the system.
     */
    public function getRoles(): array
    {
        // TODO: Implement getRoles() method.
    }

    /**
     * Returns the named role.
     *
     * @param string $name The role name.
     *
     * @return Role|null The role corresponding to the specified name. Null is returned if no such role.
     */
    public function getRoleByName(string $name): ?Role
    {
        // TODO: Implement getRoleByName() method.
    }

    /**
     * Removes all roles.
     * All parent child relations will be adjusted accordingly.
     */
    public function clearRoles(): void
    {
        // TODO: Implement clearRoles() method.
    }

    /**
     * Returns all permissions in the system.
     *
     * @return Permission[] All permissions in the system.
     */
    public function getPermissions(): array
    {
        // TODO: Implement getPermissions() method.
    }

    /**
     * Returns the named permission.
     *
     * @param string $name The permission name.
     *
     * @return Permission|null The permission corresponding to the specified name. Null is returned if no such permission.
     */
    public function getPermissionByName(string $name): ?Permission
    {
        // TODO: Implement getPermissionByName() method.
    }

    /**
     * Removes all permissions.
     * All parent child relations will be adjusted accordingly.
     */
    public function clearPermissions(): void
    {
        // TODO: Implement clearPermissions() method.
    }

    /**
     * Returns the child permissions and/or roles.
     *
     * @param string $name The parent name.
     *
     * @return Item[] The child permissions and/or roles.
     */
    public function getChildrenByName(string $name): array
    {
        // TODO: Implement getChildrenByName() method.
    }

    /**
     * Returns whether named parent has children.
     *
     * @param string $name The parent name.
     *
     * @return bool Whether named parent has children.
     */
    public function hasChildren(string $name): bool
    {
        // TODO: Implement hasChildren() method.
    }

    /**
     * Adds an item as a child of another item.
     *
     * @param Item $parent Parent to add child to.
     * @param Item $child  Child to add.
     */
    public function addChild(Item $parent, Item $child): void
    {
        // TODO: Implement addChild() method.
    }

    /**
     * Removes a child from its parent.
     * Note, the child item is not deleted. Only the parent-child relationship is removed.
     *
     * @param Item $parent Parent to remove child from.
     * @param Item $child  Child to remove.
     */
    public function removeChild(Item $parent, Item $child): void
    {
        // TODO: Implement removeChild() method.
    }

    /**
     * Removed all children form their parent.
     * Note, the children items are not deleted. Only the parent-child relationships are removed.
     *
     * @param Item $parent Parent to remove children from.
     */
    public function removeChildren(Item $parent): void
    {
        // TODO: Implement removeChildren() method.
    }

    /**
     * Returns all role assignment information.
     *
     * @return Assignment[]
     */
    public function getAssignments(): array
    {
        // TODO: Implement getAssignments() method.
    }

    /**
     * Returns all role assignment information for the specified user.
     *
     * @param string $userId The user ID.
     *
     * @return Assignment[] The assignments. An empty array will be
     * returned if there is no role assigned to the user.
     */
    public function getUserAssignments(string $userId): array
    {
        // TODO: Implement getUserAssignments() method.
    }

    /**
     * Returns role assignment for the specified item name that belongs to user with the specified ID.
     *
     * @param string $userId The user ID.
     * @param string $name   Role name.
     *
     * @return Assignment|null Assignment or null if there is no role assigned to the user.
     */
    public function getUserAssignmentByName(string $userId, string $name): ?Assignment
    {
        // TODO: Implement getUserAssignmentByName() method.
    }

    /**
     * Adds assignment of the role to the user with ID specified.
     *
     * @param string $userId The user ID.
     * @param Item   $item   Role to assign.
     */
    public function addAssignment(string $userId, Item $item): void
    {
        // TODO: Implement addAssignment() method.
    }

    /**
     * Returns whether there is assignment for a named role or permission.
     *
     * @param string $name Name of the role or the permission.
     *
     * @return bool Whether there is assignment.
     */
    public function assignmentExist(string $name): bool
    {
        // TODO: Implement assignmentExist() method.
    }

    /**
     * Removes assignment of a role to the user with ID specified.
     *
     * @param string $userId The user ID.
     * @param Item   $item   Role to remove assignment to.
     */
    public function removeAssignment(string $userId, Item $item): void
    {
        // TODO: Implement removeAssignment() method.
    }

    /**
     * Removes all role assignments for a user with ID specified.
     *
     * @param string $userId The user ID.
     */
    public function removeAllAssignments(string $userId): void
    {
        // TODO: Implement removeAllAssignments() method.
    }

    /**
     * Removes all role assignments.
     */
    public function clearAssignments(): void
    {
        // TODO: Implement clearAssignments() method.
    }

    /**
     * Returns all rules available in the system.
     *
     * @return Rule[] The rules indexed by the rule names.
     */
    public function getRules(): array
    {
        // TODO: Implement getRules() method.
    }

    /**
     * Returns the rule of the specified name.
     *
     * @param string $name The rule name.
     *
     * @return Rule|null The rule object, or null if the specified name does not correspond to a rule.
     */
    public function getRuleByName(string $name): ?Rule
    {
        // TODO: Implement getRuleByName() method.
    }

    /**
     * Removes the rule of the specified name from RBAC system.
     *
     * @param string $name The rule name.
     */
    public function removeRule(string $name): void
    {
        // TODO: Implement removeRule() method.
    }

    /**
     * Adds the rule to RBAC system.
     *
     * @param Rule $rule The rule to add.
     */
    public function addRule(Rule $rule): void
    {
        // TODO: Implement addRule() method.
}/**
     * Removes all rules.
     * All roles and permissions which have rules will be adjusted accordingly.
     */public function clearRules() : void{
 // TODO: Implement clearRules() method.
}}