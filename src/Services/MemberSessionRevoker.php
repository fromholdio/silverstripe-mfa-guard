<?php

namespace Fromholdio\MFAGuard\Services;

use SilverStripe\Core\Injector\Injectable;
use SilverStripe\Security\Member;
use SilverStripe\Security\RememberLoginHash;
use SilverStripe\SessionManager\Models\LoginSession;

/**
 * Ends every session a member has open, on every device, so a reset leaves
 * nothing signed in that began with the old credentials.
 *
 * A reset is the answer to a lost or compromised phone or account. Both of
 * the resets this module supports change credentials, not sessions: the
 * account reset email changes the password and removes the MFA methods, and
 * the break-glass task removes the MFA methods. Without this, a session
 * already open somewhere else, such as a stolen laptop or someone else's
 * browser, kept working after either. Both paths call revokeAllSessions(), so
 * they end sessions the same way:
 *
 * - AccountResetSessionExtension, when the member completes an account reset.
 * - MFAResetTask, the break-glass task, after it removes the methods.
 *
 * How a session ends. silverstripe/session-manager, a direct dependency of
 * this module, writes a LoginSession row at every login and keeps its ID in
 * the PHP session. LoginSessionMiddleware logs the member out, on that
 * session's next request, whenever the row is missing. Deleting the rows is
 * therefore session-manager's own way of ending a session: the "Log out" a
 * member can choose on one of their sessions in their profile
 * (LoginSessionController::remove()) does exactly that. It reaches every
 * device, needs no request, so it works from the command line, and never
 * touches PHP's session storage, which cannot be searched by member anyway.
 *
 * Remember-login tokens go too. "Keep me signed in" is off
 * (Security.autologin_enabled: false), so a RememberLoginHash is dormant, but
 * rows written while autologin was enabled could still exist and would start
 * a fresh session if it were ever turned back on. They are removed first, so
 * no token outlives the reset even briefly.
 *
 * Each record is deleted through the ORM, one by one. The member's
 * LoginSessions() relation is not emptied with removeAll(): on a has_many
 * list that unlinks each row (MemberID 0) instead of deleting it, which
 * would still log the session out but leave orphan rows behind.
 *
 * Which sessions end. Every session the member has when this runs ends,
 * each logged out at its next request, including one in the current request
 * if it belongs to them. A sign-in still in flight is not guaranteed to be
 * caught: the rows are read and deleted in separate queries, with no lock
 * against a login completing in between, so a login that writes its row
 * after that read survives. Both callers remove the MFA methods first, which
 * narrows that window without closing it.
 */
class MemberSessionRevoker
{
    use Injectable;


    /**
     * Revocation
     * ----------------------------------------------------
     */

    /**
     * Ends every login session the member has and removes their remember-login
     * tokens. Returns how many of each were removed. A member that has not
     * been written yet has nothing to end, and its ID of 0 must never match
     * the unlinked rows other members may have left.
     *
     * @return array{loginSessions: int, rememberLoginHashes: int}
     */
    public function revokeAllSessions(Member $member): array
    {
        if (!$member->exists())
        {
            return [
                'loginSessions' => 0,
                'rememberLoginHashes' => 0,
            ];
        }

        $rememberLoginHashCount = $this->removeRememberLoginHashes($member);
        $loginSessionCount = $this->removeLoginSessions($member);
        return [
            'loginSessions' => $loginSessionCount,
            'rememberLoginHashes' => $rememberLoginHashCount,
        ];
    }

    /**
     * Deletes the member's remember-login tokens and returns how many there
     * were.
     */
    protected function removeRememberLoginHashes(Member $member): int
    {
        $count = 0;
        $hashes = RememberLoginHash::get()->filter('MemberID', (int) $member->ID);
        foreach ($hashes as $hash)
        {
            $hash->delete();
            $count++;
        }
        return $count;
    }

    /**
     * Deletes the member's login sessions and returns how many there were.
     * LoginSessionMiddleware logs each one out at its next request.
     */
    protected function removeLoginSessions(Member $member): int
    {
        $count = 0;
        $loginSessions = LoginSession::get()->filter('MemberID', (int) $member->ID);
        foreach ($loginSessions as $loginSession)
        {
            $loginSession->delete();
            $count++;
        }
        return $count;
    }
}
