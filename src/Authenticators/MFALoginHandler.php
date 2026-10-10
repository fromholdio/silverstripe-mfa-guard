<?php

namespace Fromholdio\MFAGuard\Authenticators;

use SilverStripe\Control\HTTPRequest;
use SilverStripe\Control\HTTPResponse;
use SilverStripe\Core\Validation\ValidationResult;
use SilverStripe\MFA\Authenticator\LoginHandler;
use SilverStripe\Security\Member;
use SilverStripe\Security\MemberAuthenticator\MemberLoginForm;
use SilverStripe\Security\Security;

/**
 * silverstripe/mfa's login handler with two changes, installed by an
 * Injector replacement of SilverStripe\MFA\Authenticator\LoginHandler in
 * _config/mfa.yml. The MFA module's MemberAuthenticator returns
 * LoginHandler::create(), so the replacement governs every login.
 *
 * 1. One password check per submit (silverstripe-mfa#421). The MFA module's
 *    doLogin() runs checkLogin(), then for a wrong password, or a member MFA
 *    does not apply to, hands over to the framework's doLogin(), which runs
 *    checkLogin() again. Each check records a LoginAttempt and a failed
 *    login, so a wrong password counted twice and an account locked after
 *    half of Member.lock_out_after_incorrect_logins. doLogin() here runs the
 *    one real check, keeps [member, result] for the rest of that call, and
 *    checkLogin() hands the stored result to the second call. All of the
 *    MFA module's and the framework's doLogin() code still runs, in the same
 *    order and with the same extension hooks, so no login logic is copied.
 *    This part is adapted from SingleCheckLoginHandler in
 *    restruct/silverstripe-mfa-bundle 1.6.0 (MIT licence, copyright
 *    Restruct); see THIRD-PARTY-NOTICES.md. It is adapted rather than
 *    required because that bundle also depends on the WebAuthn module.
 *
 * 2. A session marker of MFA completion. The MFA module completes a login in
 *    doPerformLogin() after verification, after registration and after a
 *    permitted skip, then fires afterLogin, the same hook a password-only
 *    login fires; nothing records that this session passed MFA. The
 *    override here calls the parent and then, when the member who completed
 *    MFA is now the logged-in member, stores their ID under
 *    SESSION_VERIFIED_MEMBER_ID. IdentityStore::logIn() regenerates the
 *    session ID but keeps its data, and the value is written after it, so
 *    the marker lives in the regenerated session; logging out destroys the
 *    session and the marker with it. MFASessionGuardMiddleware logs out any
 *    enforced member whose session lacks it, on every request, which closes
 *    every password-only way in: forgotten password for an unenrolled
 *    member (silverstripe-mfa#516), the CMS re-login popup, a remember-login
 *    cookie, and sessions from before MFA was deployed.
 *
 * Both rest on the MFA module's doLogin() and checkLogin() (public) and
 * doPerformLogin() (protected), so silverstripe/mfa is constrained to a
 * tested minor line and the module's tests catch behavioural drift on
 * update.
 */
class MFALoginHandler extends LoginHandler
{
    /**
     * The session key holding the ID of the member who completed MFA in this
     * session. Public so a host's functional tests can mark a test login as
     * verified without repeating the key.
     */
    public const SESSION_VERIFIED_MEMBER_ID = 'MFAGuardVerifiedMemberID';

    /**
     * [member or null, ValidationResult] from the one real password check,
     * set only while doLogin() runs.
     */
    protected ?array $checkedLogin = null;


    /**
     * Core
     * ----------------------------------------------------
     */

    public function doLogin(mixed $data, MemberLoginForm $form, HTTPRequest $request): HTTPResponse
    {
        // The one real check: checkedLogin is still null here, so this
        // reaches the authenticator.
        $member = $this->checkLogin($data, $request, $result);
        $this->checkedLogin = [$member, $result];

        try
        {
            // The MFA module's doLogin() and, through it, the framework's
            // doLogin() now receive the stored result.
            return parent::doLogin($data, $form, $request);
        }
        finally
        {
            // A later login on the same handler must check again.
            $this->checkedLogin = null;
        }
    }

    public function checkLogin(mixed $data, HTTPRequest $request, ?ValidationResult &$result = null): ?Member
    {
        if (!is_null($this->checkedLogin))
        {
            [$member, $result] = $this->checkedLogin;
            return $member;
        }
        return parent::checkLogin($data, $request, $result);
    }


    /**
     * Hooks
     * ----------------------------------------------------
     */

    /**
     * Completes the login as the MFA module does, then marks the session as
     * having passed MFA for this member. The marker is written only when the
     * member who completed MFA is the member now logged in: the parent does
     * not log anyone in when someone is already logged in, and that other
     * member has not passed MFA here.
     */
    protected function doPerformLogin(HTTPRequest $request, Member $member): void
    {
        parent::doPerformLogin($request, $member);

        $currentMember = Security::getCurrentUser();
        if (is_null($currentMember) || (int) $currentMember->ID !== (int) $member->ID)
        {
            return;
        }
        $request->getSession()->set(static::SESSION_VERIFIED_MEMBER_ID, (int) $member->ID);
    }


    /**
     * Getters
     * ----------------------------------------------------
     */

    /**
     * The ID of the member who completed MFA in this request's session, or
     * null when nobody has.
     */
    public static function getVerifiedMemberID(HTTPRequest $request): ?int
    {
        $value = $request->getSession()->get(static::SESSION_VERIFIED_MEMBER_ID);
        if (is_null($value) || !is_numeric($value))
        {
            return null;
        }
        return (int) $value;
    }
}
