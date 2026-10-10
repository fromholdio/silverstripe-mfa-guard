<?php

namespace Fromholdio\MFAGuard\Services;

use SilverStripe\MFA\Service\EnforcementManager;
use SilverStripe\Security\Member;

/**
 * Makes the MFA requirement a matter of code and config rather than a CMS
 * setting.
 *
 * silverstripe/mfa reads whether MFA is required, and whether a grace period
 * applies, from two SiteConfig fields under Settings > Access. Any
 * administrator could untick that box and every CMS member could then skip
 * enrolment. This subclass replaces EnforcementManager through the Injector
 * (_config/mfa.yml in this module), and every decision the MFA module makes
 * reaches it that way: LoginHandler, SchemaGenerator, RegisteredMethodManager
 * and RegisteredMFAMethodListField all resolve it through singleton(),
 * create() or Injector::inst()->get(). So:
 *
 * - isMFARequired() returns the is_mfa_required config value and ignores
 *   SiteConfig; SiteConfigMFAExtension hides the two fields that no longer
 *   mean anything.
 * - isGracePeriodInEffect() is always false: each person enrols at their
 *   first sign-in.
 * - isMFAEnforcedFor() is the one question MFASessionGuardMiddleware asks:
 *   must this member have passed MFA in this session to count as logged in?
 *
 * The MFA module's other config is unchanged and still read from the base
 * class: enabled (BYPASS_MFA sets it false), requires_admin_access (true, so
 * MFA applies to every member with CMS access) and required_mfa_methods.
 * Config set on EnforcementManager in YAML is inherited here, so the
 * BYPASS_MFA fragment still switches enforcement off.
 *
 * isMFAEnforcedFor() uses the MFA module's own isEnabled(), which is false
 * when enabled is off or when no method other than backup codes is
 * configured. It can therefore only be true when shouldRedirectToMFA() is
 * also true for the same member, so the guard never demands a marker the
 * login flow would not have offered a way to earn.
 *
 * The supported profile is mandatory MFA for CMS members. Setting
 * is_mfa_required to false switches the guard off as well, but it does not
 * make MFA optional in a guarded way: see docs/compatibility.md.
 */
class ConfiguredEnforcementManager extends EnforcementManager
{
    /**
     * Whether every eligible member must complete MFA. The one switch; it
     * replaces the SiteConfig MFARequired field.
     */
    private static bool $is_mfa_required = true;


    /**
     * Requirement
     * ----------------------------------------------------
     */

    public function isMFARequired(): bool
    {
        return (bool) static::config()->get('is_mfa_required');
    }

    public function isGracePeriodInEffect(): bool
    {
        return false;
    }

    /**
     * Whether this member must have passed MFA in the current session before
     * reaching a guarded route: MFA is enabled with a usable method, it is
     * required, and the member has CMS access when requires_admin_access is
     * set.
     */
    public function isMFAEnforcedFor(Member $member): bool
    {
        if (!$this->isEnabled())
        {
            return false;
        }
        if (!$this->isMFARequired())
        {
            return false;
        }
        if (static::config()->get('requires_admin_access') && !$this->hasAdminAccess($member))
        {
            return false;
        }
        return true;
    }
}
