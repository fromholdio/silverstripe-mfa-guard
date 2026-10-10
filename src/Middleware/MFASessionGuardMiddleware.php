<?php

namespace Fromholdio\MFAGuard\Middleware;

use Fromholdio\MFAGuard\Authenticators\MFALoginHandler;
use Fromholdio\MFAGuard\Services\ConfiguredEnforcementManager;
use LogicException;
use SilverStripe\Control\Controller;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Control\HTTPResponse;
use SilverStripe\Control\Middleware\HTTPMiddleware;
use SilverStripe\Core\Config\Configurable;
use SilverStripe\Core\Injector\Injectable;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\MFA\Service\EnforcementManager;
use SilverStripe\Security\IdentityStore;
use SilverStripe\Security\Member;
use SilverStripe\Security\Security;

/**
 * Ends any session in which a member MFA applies to is logged in without
 * having passed MFA. One invariant, checked on every request: a member MFA is
 * enforced for counts as logged in only if this session carries
 * MFALoginHandler's marker for that same member. Otherwise they are logged
 * out before the request goes on.
 *
 * silverstripe/mfa puts its second step inside the login form's flow, so any
 * other way of becoming logged in skips it. This guard closes them all at the
 * door rather than one by one:
 *
 * - Forgotten password (silverstripe-mfa#516): the framework logs a member in
 *   after a password reset, and the MFA module asks for MFA there only when
 *   the member already has a registered method. An unenrolled member would be
 *   logged in with CMS permissions; here they are logged out on their next
 *   request, and the login then requires enrolment. An enrolled member
 *   enters a code during the reset, and MFAChangePasswordHandler writes the
 *   marker for them only when that code was theirs and for that reset.
 * - The CMS re-login popup, which re-authenticates with the password alone.
 *   CMSSecurity.reauth_enabled is false in _config/mfa.yml; this is the
 *   second line.
 * - "Keep me signed in", if Security.autologin_enabled is ever switched back
 *   on (silverstripe-mfa#384): the cookie starts a session with no marker.
 * - Sessions that were logged in before MFA was deployed.
 * - Any future password-only path through the same middleware chain.
 *
 * Why every request and not only the CMS. A logged-in member's CMS
 * permissions apply wherever the site checks them, not only under admin:
 * draft pages through ?stage=Stage, archived versions through ?archiveDate=,
 * protected and draft files under assets/, and anything else gated on a
 * permission. Guarding only the CMS routes would leave all of that open to a
 * session that skipped MFA. Anonymous visitors are never logged in, so the
 * check costs them nothing; for a logged-in member it is one session read,
 * and the enforcement question (which walks the CMS menu) is asked only when
 * the marker is missing.
 *
 * What happens after the log-out depends on the path:
 *
 * - The CMS-facing prefixes in guarded_path_prefixes (admin, dev): a
 *   redirect to the login with the requested path as BackURL. An XHR request
 *   (the CMS loads its panels that way) gets the 403 "Not logged in" answer
 *   Security::permissionFailure() gives instead, so the CMS shows a message
 *   rather than rendering the login page inside a panel.
 * - Every other path: the request carries on as an anonymous visitor's would,
 *   so a public page is never redirected to the login by this guard.
 *
 * The MFA flow itself is untouched: during the password and MFA steps the
 * member is held in the MFA store, not logged in, until
 * MFALoginHandler::doPerformLogin() logs them in and writes the marker in
 * the same request. The log-out goes through the IdentityStore, which
 * destroys the session (and any marker with it) and clears the remember-login
 * cookie.
 *
 * Registered on the Director middleware chain in _config/middleware.yml,
 * ordered after #coresecurity so AuthenticationMiddleware has already
 * resolved the current member, and before #versionedrequestprocessors so
 * VersionedHTTPMiddleware and the controllers see the anonymous visitor;
 * MFASessionGuardMiddlewareTest pins the order. With BYPASS_MFA set,
 * EnforcementManager.enabled is false and the guard passes everything.
 */
class MFASessionGuardMiddleware implements HTTPMiddleware
{
    use Configurable;
    use Injectable;

    /**
     * The first path segment of every CMS-facing request, which is redirected
     * to the login after an unverified member is logged out. A request matches
     * when its path is the prefix or starts with the prefix and a slash.
     */
    private static array $guarded_path_prefixes = [
        'admin',
        'dev',
    ];


    /**
     * Core
     * ----------------------------------------------------
     */

    public function process(HTTPRequest $request, callable $delegate): ?HTTPResponse
    {
        $member = Security::getCurrentUser();
        if (is_null($member))
        {
            return $delegate($request);
        }

        if ($this->isSessionVerifiedFor($request, $member))
        {
            return $delegate($request);
        }

        if (!$this->getEnforcementManager()->isMFAEnforcedFor($member))
        {
            return $delegate($request);
        }

        $this->logOut($request);

        if ($this->isGuardedPath($request))
        {
            return $this->refuse($request);
        }
        return $delegate($request);
    }

    /**
     * Ends the session through the IdentityStore: the session is destroyed and
     * the current user is cleared for the rest of this request.
     */
    protected function logOut(HTTPRequest $request): void
    {
        Injector::inst()->get(IdentityStore::class)->logOut($request);
    }

    /**
     * The answer on a CMS-facing path once the member is logged out: the full
     * login, which now requires MFA, or a 403 for an XHR request.
     */
    protected function refuse(HTTPRequest $request): HTTPResponse
    {
        if ($request->isAjax())
        {
            $message = _t(
                'SilverStripe\\CMS\\Controllers\\ContentController.NOTLOGGEDIN',
                'Not logged in'
            );
            return HTTPResponse::create($message, 403)->setStatusDescription($message);
        }

        $backURL = '/' . ltrim($request->getURL(true), '/');
        $loginURL = Controller::join_links(
            Security::login_url(),
            '?BackURL=' . urlencode($backURL)
        );
        return HTTPResponse::create()->redirect($loginURL);
    }


    /**
     * Getters
     * ----------------------------------------------------
     */

    protected function isGuardedPath(HTTPRequest $request): bool
    {
        $path = (string) $request->getURL();
        $prefixes = (array) static::config()->get('guarded_path_prefixes');
        foreach ($prefixes as $prefix)
        {
            $prefix = (string) $prefix;
            if ($path === $prefix || str_starts_with($path, $prefix . '/'))
            {
                return true;
            }
        }
        return false;
    }

    protected function isSessionVerifiedFor(HTTPRequest $request, Member $member): bool
    {
        return MFALoginHandler::getVerifiedMemberID($request) === (int) $member->ID;
    }

    /**
     * The enforcement manager the MFA module itself uses, which this module's
     * _config/mfa.yml replaces with ConfiguredEnforcementManager. Anything
     * else means the replacement is missing or another module has replaced
     * the same service, and the guard refuses to guess.
     */
    protected function getEnforcementManager(): ConfiguredEnforcementManager
    {
        $manager = Injector::inst()->get(EnforcementManager::class);
        if (!($manager instanceof ConfiguredEnforcementManager))
        {
            throw new LogicException(sprintf(
                'MFASessionGuardMiddleware needs %s replaced by %s in the Injector'
                . ' (see _config/mfa.yml in fromholdio/silverstripe-mfa-guard)',
                EnforcementManager::class,
                ConfiguredEnforcementManager::class
            ));
        }
        return $manager;
    }
}
