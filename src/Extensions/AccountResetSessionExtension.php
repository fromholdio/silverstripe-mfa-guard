<?php

namespace Fromholdio\MFAGuard\Extensions;

use Fromholdio\MFAGuard\Services\MemberSessionRevoker;
use SilverStripe\Core\Extension;
use SilverStripe\MFA\Extension\AccountReset\SecurityExtension;
use SilverStripe\Security\Member;

/**
 * Ends every session the member had open when they complete an account reset.
 *
 * The account reset an administrator sends from Security exists for a member
 * who has lost their phone and backup codes, or whose account may be
 * compromised. silverstripe/mfa's SecurityExtension::doResetAccount() changes
 * the password, clears the lockout and then fires handleAccountReset, where
 * the MFA module's own MFAResetExtension removes the MFA methods. Sessions
 * were left alone, so one already open on another device kept working with
 * the old credentials. This extension sits on the same hook, ordered after
 * the MFA module's in _config/mfa.yml, and ends them all through
 * MemberSessionRevoker; each is logged out at its next request.
 *
 * When it runs. Only on completion: the member has followed the emailed link
 * and set a new password. Sending the email changes nothing, so an
 * administrator's send never signs anyone out; until the member completes
 * the reset their old credentials still work, and ending sessions then would
 * only make whoever holds them sign in again.
 *
 * Nothing is kept. The reset logs nobody in: its page refuses a logged-in
 * visitor ("You must be logged out to reset your account.") and the form
 * ends with a redirect to the login. So there is no session of the reset to
 * preserve, and every session of the member ends, including one opened in
 * another tab between the link and the form. The member then signs in with
 * the new password and enrols in MFA again.
 *
 * @extends Extension<SecurityExtension>
 */
class AccountResetSessionExtension extends Extension
{
    /**
     * Hooks
     * ----------------------------------------------------
     */

    protected function handleAccountReset(Member $member): void
    {
        MemberSessionRevoker::singleton()->revokeAllSessions($member);
    }
}
