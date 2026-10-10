<?php

namespace Fromholdio\MFAGuard\Tests\Support;

use Fromholdio\MFAGuard\Authenticators\MFALoginHandler;
use SilverStripe\Security\Member;
use SilverStripe\Security\Security;

/**
 * For functional tests that reach the CMS or dev routes with a test login
 * (logInWithPermission(), logInAs()). Those log a member in without the MFA
 * step, so MFASessionGuardMiddleware refuses them, as it should. This marks
 * the test session as having passed MFA for that member, exactly as
 * MFALoginHandler::doPerformLogin() does after a real MFA login, so the tests
 * keep exercising the guard rather than switching enforcement off.
 *
 * A host project's own tests can do the same with a few lines of their own:
 * set MFALoginHandler::SESSION_VERIFIED_MEMBER_ID in the test session to the
 * member's ID. This trait lives under the module's test namespace, which a
 * host does not autoload (see docs/testing.md).
 */
trait MFASessionMarker
{
    /**
     * Marks the test session as MFA-verified for the given member, or for the
     * member currently logged in.
     */
    protected function markSessionMFAVerified(?Member $member = null): void
    {
        $member = $member ?? Security::getCurrentUser();
        if (is_null($member))
        {
            $this->fail('markSessionMFAVerified() needs a logged-in member');
        }
        $this->session()->set(MFALoginHandler::SESSION_VERIFIED_MEMBER_ID, (int) $member->ID);
    }
}
