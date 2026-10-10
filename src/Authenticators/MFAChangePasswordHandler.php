<?php

namespace Fromholdio\MFAGuard\Authenticators;

use SilverStripe\Control\HTTPRequest;
use SilverStripe\Control\HTTPResponse;
use SilverStripe\MFA\Authenticator\ChangePasswordHandler;
use SilverStripe\MFA\Authenticator\LoginHandler;
use SilverStripe\MFA\Service\EnforcementManager;
use SilverStripe\Security\Member;
use SilverStripe\Security\Security;

/**
 * silverstripe/mfa's change-password handler, changed so that an enrolled
 * member's forgotten-password reset asks for one code and ends logged in
 * with MFA done. Installed by an Injector replacement of
 * SilverStripe\MFA\Authenticator\ChangePasswordHandler in _config/mfa.yml;
 * MFA's MemberAuthenticator returns ChangePasswordHandler::create(), so the
 * replacement governs every reset.
 *
 * The problem. The module asks an enrolled member for a code before the
 * new-password form, and the framework then logs them in. Nothing marks that
 * session as having passed MFA, so MFASessionGuardMiddleware logs them out
 * on the next request and they sign in again with password and code: two
 * codes for one reset. The module's own record of the code is no basis for
 * the marker, because of three gaps in silverstripe/mfa 6.2:
 *
 * 1. Its flag, MFA_VERIFIED_ON_CHANGE_PASSWORD, is a bare true. It is set
 *    for whichever member the MFA store holds, then honoured for whichever
 *    member's reset hash is in the session, and it outlives the reset it was
 *    set in. Someone who passes MFA for their own account's reset, then
 *    opens another member's reset link in the same browser, is shown that
 *    member's form. The store is shared with the login handler, so a
 *    password step at the login can also point it at a different account.
 * 2. It gates only the display of the form. doChangePassword() is the
 *    framework's and never checks MFA, so a direct post of the form changes
 *    an enrolled member's password without a code, and, because a reset
 *    clears the lockout, resets their failed-attempt count.
 * 3. Its code prompt, verifyMFACheck(), neither refuses a locked-out member
 *    nor counts a wrong code, where the login's finishVerification() does
 *    both. Once a reset logs the member in with MFA done, that prompt is a
 *    way into the CMS and must be throttled like the login.
 *
 * What this class does, by wrapping the module's methods (no upstream
 * method body is copied):
 *
 * - verifyMFACheck() refuses a locked-out member and registers a failed
 *   login for each wrong code, as the login does. When the module reports
 *   the code complete, it records the verification in the session under
 *   SESSION_VERIFIED_RESET, bound to the member's ID and a SHA-256 digest of
 *   the reset's AutoLoginHash, but only if the member who passed MFA is the
 *   member that reset hash belongs to. Otherwise the module's flag is
 *   cleared and the answer is 403.
 * - createChangePasswordResponse() forgets the record and clears the
 *   module's flag unless the record matches the live reset now in the
 *   session, so the module asks for that member's code again rather than
 *   trusting a code passed for another member or another reset.
 * - doChangePassword() refuses the new password for a reset of a member
 *   with registered methods unless the bound record matches, sending the
 *   browser back to the code prompt; this is the rule the module applies to
 *   showing the form, now applied to submitting it. After the framework has
 *   changed the password and logged the member in, it writes
 *   MFALoginHandler::SESSION_VERIFIED_MEMBER_ID for that member under the
 *   two rules the login applies before it logs anyone in: the member who
 *   passed MFA is the member now logged in (MFALoginHandler::
 *   doPerformLogin()), and their MFA registration is complete
 *   (EnforcementManager::hasCompletedRegistration(), which the module's
 *   finishVerification() and finishRegistration() check). A member who
 *   registered an authenticator app but stopped before saving their
 *   recovery codes gets no marker, so the guard logs them out and their
 *   next sign-in makes them finish registering.
 *
 * When the record is forgotten. Each time createChangePasswordResponse() or
 * doChangePassword() runs, the record and the module's flag are cleared
 * together unless the record matches the live reset now in the session:
 * after the password has changed, when the hash has expired or been
 * replaced, when another reset link has been opened, or when a logged-in
 * change has spent the hash. Logging out destroys the session and both
 * with it.
 *
 * Some requests end before either method runs and can leave both keys
 * behind: an emailed token link the framework rejects as expired or
 * invalid, which it answers from processChangePasswordUrlVars(); a
 * submission refused by form validation (empty fields, for example), which
 * never reaches the action; and a reset that is simply abandoned. A
 * retained record stays usable only for the same live reset: it counts
 * only through isResetVerifiedFor(), which needs the session's current
 * reset hash to resolve to the same unexpired member and to match the
 * record's digest. After a validation refusal on a live reset that is
 * deliberate, so the member can correct the form without another code. A
 * stale record, whose hash has been spent, has expired or has been
 * replaced, grants no reset authority, and a new reset brings a new hash.
 * The module's flag is read only by its createChangePasswordResponse(),
 * which this class runs after clearing the flag unless the record matches,
 * and the submission gate checks the record, never the flag. A later
 * request clears both keys when it reaches one of the two methods and the
 * record no longer matches a live reset (another rejected token link does
 * not reach them); ending the session also removes them.
 *
 * Why the binding holds. A reset's AutoLoginHash belongs to one member, is
 * replaced when a new reset is requested, and is cleared from the member
 * and the session when the password changes. A record for another member,
 * an earlier reset, or a store swapped at the login therefore never
 * matches, and the guard still sends that session through MFA as the
 * member it belongs to. The digest keeps a second copy of the reset hash
 * out of the session.
 *
 * Unchanged. A member without registered methods is never asked for a code,
 * is logged in by the framework without a marker, and is logged out by the
 * guard, so their next sign-in requires enrolment (silverstripe-mfa#516). A
 * logged-in member changing their own password with their current one
 * passes straight through. MFASessionGuardMiddleware is not touched: it
 * still requires the marker.
 *
 * Upstream reliance. The wrappers depend on verifyMFACheck() answering 200
 * when the code is complete and 401 when it is wrong, on the module's flag
 * and the framework's AutoLoginHash session key, on doChangePassword()
 * logging the member in and clearing that key on success, and on
 * EnforcementManager::hasCompletedRegistration() being the login's test of
 * a finished enrolment. MFAChangePasswordHandlerTest exercises each of these
 * through the real endpoints, so silverstripe/mfa stays on a tested minor
 * line and those tests must pass after any update.
 */
class MFAChangePasswordHandler extends ChangePasswordHandler
{
    /**
     * The session key holding the member who passed MFA during a reset, and
     * which reset: ['MemberID' => int, 'HashDigest' => SHA-256 of the
     * reset's AutoLoginHash].
     */
    public const SESSION_VERIFIED_RESET = 'MFAGuardVerifiedPasswordReset';

    /**
     * The session key the framework's change-password handler keeps a
     * reset's hash under.
     */
    public const SESSION_AUTO_LOGIN_HASH = 'AutoLoginHash';

    /**
     * RequestHandler checks an action against the allowed_actions of the
     * class that defines its method, so overriding verifyMFACheck() moves it
     * here. The module's url_handlers and its other actions are inherited
     * through config unchanged.
     */
    private static array $allowed_actions = [
        'verifyMFACheck',
    ];


    /**
     * Core
     * ----------------------------------------------------
     */

    /**
     * The module's code check, throttled as the login's is, and recorded
     * only for the member whose reset is in this session.
     */
    public function verifyMFACheck(HTTPRequest $request): HTTPResponse
    {
        $store = $this->getStore();
        $member = is_null($store) ? null : $store->getMember();
        if (is_null($member))
        {
            return parent::verifyMFACheck($request);
        }

        if ($member->isLockedOut())
        {
            return $this->jsonResponse([
                'message' => _t(
                    LoginHandler::class . '.LOCKED_OUT',
                    'Your account is temporarily locked. Please try again later.'
                ),
            ], 403);
        }

        $response = parent::verifyMFACheck($request);
        $status = $response->getStatusCode();
        if ($status === 401)
        {
            $member->registerFailedLogin();
            return $response;
        }
        if ($status !== 200)
        {
            return $response;
        }

        if ($this->isResetMember($request, $member))
        {
            $this->recordVerifiedReset($request, $member);
            return $response;
        }

        // A complete code, but not from the member this session's reset
        // belongs to: the module has already set its flag, so take it back.
        $this->forgetVerifiedReset($request);
        return $this->jsonResponse(['message' => 'Forbidden'], 403);
    }

    /**
     * The module's page for a reset, with its flag honoured only when the
     * bound record matches the live reset in this session. Anything else is
     * forgotten, so the module asks for the code again.
     */
    protected function createChangePasswordResponse(): array|HTTPResponse
    {
        $this->forgetUnlessVerifiedForLiveReset($this->getRequest());
        return parent::createChangePasswordResponse();
    }

    /**
     * The new password for a reset: refused for an enrolled member without
     * a code bound to this reset, and ending with the MFA marker when there
     * is one and the member's registration is complete.
     */
    public function doChangePassword(array $data, mixed $form): array|HTTPResponse
    {
        $request = $this->getRequest();

        // With nobody logged in, the framework changes the password of the
        // member whose reset is in the session. A logged-in member changes
        // their own with their current one, and the reset plays no part.
        $resetMember = is_null(Security::getCurrentUser()) ? $this->getResetMember($request) : null;
        $isVerified = !is_null($resetMember) && $this->isResetVerifiedFor($request, $resetMember);

        if (!is_null($resetMember) && !$isVerified && $resetMember->RegisteredMFAMethods()->exists())
        {
            $this->forgetVerifiedReset($request);
            return $this->redirectBackToForm();
        }

        $response = parent::doChangePassword($data, $form);

        if ($isVerified)
        {
            $this->markSessionVerified($request, $resetMember);
        }

        // Once this action has run, a record or module flag that no longer
        // matches the live reset is cleared: the password changed, the hash
        // proved expired or invalid, or a logged-in change spent it. A new
        // password the framework refuses leaves the live reset, and its
        // verification, for the next try. A submission refused by form
        // validation never reaches this action, so nothing is cleared: a
        // record for a still-live reset stays usable for that reset's retry,
        // and a stale one grants nothing (see the class docblock).
        $this->forgetUnlessVerifiedForLiveReset($request);
        return $response;
    }


    /**
     * Getters
     * ----------------------------------------------------
     */

    /**
     * The reset hash the framework holds in this session, or null when no
     * reset is under way.
     */
    protected function getResetHash(HTTPRequest $request): ?string
    {
        $hash = $request->getSession()->get(static::SESSION_AUTO_LOGIN_HASH);
        if (!is_string($hash) || $hash === '')
        {
            return null;
        }
        return $hash;
    }

    /**
     * The member whose unexpired reset is in this session, or null.
     */
    protected function getResetMember(HTTPRequest $request): ?Member
    {
        $hash = $this->getResetHash($request);
        if (is_null($hash))
        {
            return null;
        }
        return Member::member_from_autologinhash($hash);
    }

    protected function isResetMember(HTTPRequest $request, Member $member): bool
    {
        $resetMember = $this->getResetMember($request);
        return !is_null($resetMember) && (int) $resetMember->ID === (int) $member->ID;
    }

    /**
     * Whether this session holds a code passed by this member for the reset
     * now in the session.
     */
    protected function isResetVerifiedFor(HTTPRequest $request, Member $member): bool
    {
        $hash = $this->getResetHash($request);
        $record = $request->getSession()->get(static::SESSION_VERIFIED_RESET);
        if (is_null($hash) || !is_array($record))
        {
            return false;
        }

        $memberID = $record['MemberID'] ?? null;
        $digest = $record['HashDigest'] ?? null;
        if (!is_numeric($memberID) || !is_string($digest))
        {
            return false;
        }
        return (int) $memberID === (int) $member->ID
            && hash_equals($digest, $this->getHashDigest($hash));
    }

    protected function getHashDigest(string $hash): string
    {
        return hash('sha256', $hash);
    }


    /**
     * Setters
     * ----------------------------------------------------
     */

    protected function recordVerifiedReset(HTTPRequest $request, Member $member): void
    {
        $hash = $this->getResetHash($request);
        if (is_null($hash))
        {
            return;
        }
        $request->getSession()->set(static::SESSION_VERIFIED_RESET, [
            'MemberID' => (int) $member->ID,
            'HashDigest' => $this->getHashDigest($hash),
        ]);
    }

    /**
     * Forgets any code passed during a reset in this session, the module's
     * flag included.
     */
    protected function forgetVerifiedReset(HTTPRequest $request): void
    {
        $session = $request->getSession();
        $session->clear(static::SESSION_VERIFIED_RESET);
        $session->clear(ChangePasswordHandler::MFA_VERIFIED_ON_CHANGE_PASSWORD);
    }

    /**
     * Forgets the record and the module's flag unless the record matches
     * the live (unexpired) reset now in the session: no reset, an expired or
     * replaced hash, or a record for another member or another reset.
     */
    protected function forgetUnlessVerifiedForLiveReset(HTTPRequest $request): void
    {
        $resetMember = $this->getResetMember($request);
        if (!is_null($resetMember) && $this->isResetVerifiedFor($request, $resetMember))
        {
            return;
        }
        $this->forgetVerifiedReset($request);
    }

    /**
     * Marks the session as having passed MFA for this member under the two
     * rules the login applies before logging anyone in:
     *
     * - They are the member now logged in, as MFALoginHandler::
     *   doPerformLogin() requires.
     * - Their MFA registration is complete, as the module's
     *   finishVerification() and finishRegistration() require. A member who
     *   registered an authenticator app but not yet their recovery codes has
     *   passed MFA for the reset but not finished enrolling, so they get no
     *   marker; the guard logs them out and the next sign-in has them finish.
     *
     * The framework's log-in has already regenerated the session ID, so the
     * marker lives in the new session.
     */
    protected function markSessionVerified(HTTPRequest $request, Member $member): void
    {
        $currentMember = Security::getCurrentUser();
        if (is_null($currentMember) || (int) $currentMember->ID !== (int) $member->ID)
        {
            return;
        }
        if (!EnforcementManager::create()->hasCompletedRegistration($member))
        {
            return;
        }
        $request->getSession()->set(MFALoginHandler::SESSION_VERIFIED_MEMBER_ID, (int) $member->ID);
    }
}
