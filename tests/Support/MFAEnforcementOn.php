<?php

namespace Fromholdio\MFAGuard\Tests\Support;

use SilverStripe\Core\Config\Config;
use SilverStripe\MFA\Service\EnforcementManager;

/**
 * For tests of CMS MFA behaviour, which assume MFA is switched on. The MFA
 * module's mfa-devconfig fragment (Only: envvarset: BYPASS_MFA) sets
 * EnforcementManager.enabled to false whenever BYPASS_MFA is in the
 * environment, with any value, even an empty one. Without this, an
 * environment with the bypass turns off exactly what these tests check.
 *
 * enableMFAEnforcement() sets it back to true on the same class, after the
 * test's config is nested, so it is undone after each test. Every reader goes
 * through EnforcementManager::isEnabled(), which reads the config on each
 * call, and ConfiguredEnforcementManager inherits the base class's value, so
 * the Injector's singleton, the login handlers and MFASessionGuardMiddleware
 * all see it. A test that needs MFA off sets enabled to false itself
 * afterwards.
 */
trait MFAEnforcementOn
{
    /**
     * Switches MFA enforcement on for this test, whatever BYPASS_MFA says.
     * Call from setUp() after parent::setUp().
     */
    protected function enableMFAEnforcement(): void
    {
        Config::modify()->set(EnforcementManager::class, 'enabled', true);
    }
}
