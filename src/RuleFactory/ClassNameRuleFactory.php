<?php

declare(strict_types=1);

namespace ffsoft\Rbac\RuleFactory;

use ffsoft\Rbac\Rule;
use ffsoft\Rbac\RuleFactoryInterface;

class ClassNameRuleFactory implements RuleFactoryInterface
{
    public function create(string $name): Rule
    {
        return new $name();
    }
}
