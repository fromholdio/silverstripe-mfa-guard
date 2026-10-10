<?php

namespace Fromholdio\MFAGuard\Tests\Security;

use Fromholdio\MFAGuard\Authenticators\MFALoginHandler;
use Fromholdio\MFAGuard\Middleware\MFASessionGuardMiddleware;
use Fromholdio\MFAGuard\Tests\Fixtures\MFAGuardProbePage;
use Fromholdio\MFAGuard\Tests\Support\MFAFunctionalTestCase;
use SilverStripe\Assets\Dev\TestAssetStore;
use SilverStripe\Assets\File;
use SilverStripe\Control\Director;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Control\HTTPResponse;
use SilverStripe\Control\Session;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\MFA\Service\EnforcementManager;
use SilverStripe\ORM\FieldType\DBDatetime;
use SilverStripe\Security\CMSSecurity;
use SilverStripe\Security\Member;
use SilverStripe\Security\Security;

/**
 * No session reaches the CMS or dev routes without passing MFA: a test login
 * with no marker, a marker for someone else, and a forgotten-password login
 * of an unenrolled member are all logged out and sent to the login; public
 * pages are never redirected. Also pins the guard's place in the
 * middleware chain, and the two settings that keep password-only doors shut:
 * the CMS re-login popup and "Keep me signed in".
 */
class MFASessionGuardMiddlewareTest extends MFAFunctionalTestCase
{
    protected static $fixture_file = 'MFATest.yml';

    protected static $extra_dataobjects = [
        MFAGuardProbePage::class,
    ];

    protected function getMember(string $fixture): Member
    {
        return $this->objFromFixture(Member::class, $fixture);
    }

    protected function assertRefusedToLogin(HTTPResponse $response, string $backURL): void
    {
        $this->assertSame(302, $response->getStatusCode());
        $location = $this->getLocation($response);
        $this->assertStringContainsString('Security/login', $location);
        $this->assertStringContainsString('BackURL=' . urlencode($backURL), $location);
        $this->assertNull($this->getLoggedInMemberID(), 'The member is logged out');
        $this->assertNull($this->getSessionMarker());
    }

    /**
     * A published page whose draft has since changed: "Live words" on the
     * live site, "Draft words" on the draft.
     */
    protected function createDraftChangedPage(): MFAGuardProbePage
    {
        $page = MFAGuardProbePage::create();
        $page->Title = 'MFA probe';
        $page->URLSegment = 'mfa-probe';
        $page->Content = '<p>Live words</p>';
        $page->write();
        $page->publishSingle();
        $page->Content = '<p>Draft words</p>';
        $page->write();
        return $page;
    }

    /**
     * A page published with "Archived words", then republished a day later
     * with "Live words". Returns a moment between the two, in the form
     * ?archiveDate= takes.
     */
    protected function createRepublishedPage(): string
    {
        DBDatetime::set_mock_now('2026-01-01 09:00:00');
        $page = MFAGuardProbePage::create();
        $page->Title = 'MFA probe';
        $page->URLSegment = 'mfa-probe';
        $page->Content = '<p>Archived words</p>';
        $page->write();
        $page->publishSingle();

        DBDatetime::set_mock_now('2026-01-02 09:00:00');
        $page->Content = '<p>Live words</p>';
        $page->write();
        $page->publishSingle();
        DBDatetime::clear_mock_now();

        return '2026-01-01 12:00:00';
    }

    /**
     * Runs the guard on its own for one request with the given member
     * current, and reports whether it passed the request on.
     */
    protected function runGuard(string $url, ?Member $member, array $headers = [], bool $isVerified = false): array
    {
        $request = new HTTPRequest('GET', $url);
        foreach ($headers as $name => $value)
        {
            $request->addHeader($name, $value);
        }
        $request->setSession(new Session([]));
        if (!is_null($member))
        {
            $request->getSession()->set('loggedInAs', $member->ID);
            if ($isVerified)
            {
                $request->getSession()->set(MFALoginHandler::SESSION_VERIFIED_MEMBER_ID, (int) $member->ID);
            }
        }
        Security::setCurrentUser($member);

        $isDelegated = false;
        $delegatedMemberID = null;
        $response = MFASessionGuardMiddleware::create()->process(
            $request,
            function (HTTPRequest $request) use (&$isDelegated, &$delegatedMemberID): HTTPResponse
            {
                $isDelegated = true;
                $delegatedMemberID = Security::getCurrentUser()?->ID;
                return HTTPResponse::create('passed', 200);
            }
        );
        return [$isDelegated, $response, $request, $delegatedMemberID];
    }


    /**
     * Tests
     * ----------------------------------------------------
     */

    public function testTheGuardRunsAfterAuthentication(): void
    {
        $names = array_keys(Injector::inst()->get(Director::class)->getMiddlewares());

        $this->assertContains('AuthenticationMiddleware', $names);
        $this->assertContains('MFASessionGuardMiddleware', $names);
        $this->assertLessThan(
            array_search('MFASessionGuardMiddleware', $names),
            array_search('AuthenticationMiddleware', $names),
            'AuthenticationMiddleware must run before (outside) the guard'
        );
        $this->assertLessThan(
            array_search('VersionedMiddleware', $names),
            array_search('MFASessionGuardMiddleware', $names),
            'The guard must run before (outside) the versioned middleware'
        );
    }

    public function testATestLoginWithoutTheMarkerIsRefusedTheCMS(): void
    {
        $this->logInAs($this->getMember('admin'));

        $this->assertRefusedToLogin($this->get('admin/pages'), '/admin/pages');
    }

    public function testATestLoginWithoutTheMarkerIsRefusedDev(): void
    {
        $this->logInAs($this->getMember('admin'));

        $this->assertRefusedToLogin($this->get('dev/tasks'), '/dev/tasks');
    }

    public function testTheBackURLKeepsTheQueryString(): void
    {
        $this->logInAs($this->getMember('editor'));

        $this->assertRefusedToLogin($this->get('admin/pages?foo=bar'), '/admin/pages?foo=bar');
    }

    public function testTheMarkerAdmitsItsOwnMember(): void
    {
        $this->logInAs($this->getMember('admin'));
        $this->markSessionMFAVerified();

        $this->assertSame(200, $this->get('admin/pages')->getStatusCode());
        $this->assertSame((int) $this->getMember('admin')->ID, $this->getLoggedInMemberID());
    }

    public function testAMarkerForAnotherMemberIsRefused(): void
    {
        $this->logInAs($this->getMember('admin'));
        $this->session()->set(MFALoginHandler::SESSION_VERIFIED_MEMBER_ID, (int) $this->getMember('otheradmin')->ID);

        $this->assertRefusedToLogin($this->get('admin/pages'), '/admin/pages');
    }

    public function testAnXHRRequestIsRefusedWithA403(): void
    {
        [$isDelegated, $response] = $this->runGuard('admin/pages', $this->getMember('editor'), ['X-Requested-With' => 'XMLHttpRequest']);

        $this->assertFalse($isDelegated);
        $this->assertSame(403, $response->getStatusCode());
        $this->assertNull(Security::getCurrentUser());
    }

    public function testAnonymousRequestsAreUntouched(): void
    {
        foreach (['', 'about-us', 'contact/form', 'search/results?q=x', 'Security/login', 'assets/file.pdf', 'admin/pages'] as $url)
        {
            [$isDelegated, $response] = $this->runGuard($url, null);
            $this->assertTrue($isDelegated, 'Passed through: /' . $url);
            $this->assertSame('passed', $response->getBody());
        }
    }

    public function testAVerifiedMemberStaysLoggedInEverywhere(): void
    {
        $admin = $this->getMember('admin');
        foreach (['', 'about-us', 'search/results?q=x', 'Security/login', 'assets/file.pdf', 'admin/pages', 'dev/tasks'] as $url)
        {
            [$isDelegated, , $request, $delegatedMemberID] = $this->runGuard($url, $admin, [], true);
            $this->assertTrue($isDelegated, 'Passed through: /' . $url);
            $this->assertSame((int) $admin->ID, (int) $delegatedMemberID, 'Still the member on /' . $url);
            $this->assertSame((int) $admin->ID, (int) $request->getSession()->get('loggedInAs'));
        }
    }

    /**
     * The invariant holds on every path. Off the CMS prefixes the request
     * carries on as an anonymous visitor's, with no redirect to the login
     * from the guard.
     */
    public function testAnUnverifiedMemberIsLoggedOutOnEveryOtherPathAndTheRequestContinues(): void
    {
        $admin = $this->getMember('admin');
        foreach (['', 'about-us', 'search/results?q=x', 'contact/form', 'Security/login', 'CMSSecurity/login', 'assets/file.pdf', 'administrator', 'devices'] as $url)
        {
            [$isDelegated, $response, $request, $delegatedMemberID] = $this->runGuard($url, $admin);
            $this->assertTrue($isDelegated, 'Continued: /' . $url);
            $this->assertSame('passed', $response->getBody(), 'No redirect on /' . $url);
            $this->assertNull($delegatedMemberID, 'Anonymous inside the request on /' . $url);
            $this->assertNull($request->getSession()->get('loggedInAs'), 'Logged out on /' . $url);
        }
    }

    /**
     * A logged-in member's permissions would otherwise reach the draft site.
     * Once logged out, the request gets exactly what an anonymous visitor
     * gets: Versioned's own draft-access refusal, never the draft.
     */
    public function testAnUnverifiedMemberCannotReadDraftContent(): void
    {
        $page = $this->createDraftChangedPage();

        $this->startFreshBrowser();
        $anonymous = $this->get('mfa-probe?stage=Stage');

        $this->startFreshBrowser();
        $this->logInAs($this->getMember('admin'));
        $response = $this->get('mfa-probe?stage=Stage');

        $this->assertStringNotContainsString('Draft words', (string) $response->getBody());
        $this->assertSame($anonymous->getStatusCode(), $response->getStatusCode(), 'The same answer an anonymous visitor gets');
        $this->assertSame($anonymous->getHeader('Location'), $response->getHeader('Location'));
        $this->assertNull($this->getLoggedInMemberID(), 'Logged out');

        $next = $this->get('mfa-probe');
        $this->assertSame(200, $next->getStatusCode());
        $this->assertStringContainsString('Live words', (string) $next->getBody());
        $this->assertNull($this->getLoggedInMemberID(), 'Still not logged in on the next request');
    }

    public function testAnUnverifiedMemberGetsTheLivePageWithoutARedirect(): void
    {
        $this->createDraftChangedPage();
        $this->logInAs($this->getMember('editor'));

        $response = $this->get('mfa-probe');

        $this->assertSame(200, $response->getStatusCode());
        $this->assertStringContainsString('Live words', (string) $response->getBody());
        $this->assertNull($this->getLoggedInMemberID());
    }

    public function testAVerifiedMemberKeepsDraftAccess(): void
    {
        $this->createDraftChangedPage();
        $this->logInAs($this->getMember('admin'));
        $this->markSessionMFAVerified();

        $response = $this->get('mfa-probe?stage=Stage');

        $this->assertSame(200, $response->getStatusCode());
        $this->assertStringContainsString('Draft words', (string) $response->getBody());
        $this->assertSame((int) $this->getMember('admin')->ID, $this->getLoggedInMemberID());
    }

    /**
     * Archived versions through ?archiveDate= with a real page history. The
     * page said "Archived words" until it was republished with "Live words";
     * only a verified member may read the earlier version.
     */
    public function testAnUnverifiedMemberCannotReadArchivedContent(): void
    {
        $archiveDate = $this->createRepublishedPage();

        $this->startFreshBrowser();
        $anonymous = $this->get('mfa-probe?archiveDate=' . urlencode($archiveDate));
        $this->assertStringNotContainsString('Archived words', (string) $anonymous->getBody());

        $this->startFreshBrowser();
        $this->logInAs($this->getMember('admin'));
        $response = $this->get('mfa-probe?archiveDate=' . urlencode($archiveDate));

        $this->assertStringNotContainsString('Archived words', (string) $response->getBody());
        $this->assertSame($anonymous->getStatusCode(), $response->getStatusCode(), 'The same answer an anonymous visitor gets');
        $this->assertSame($anonymous->getHeader('Location'), $response->getHeader('Location'));
        $this->assertNull($this->getLoggedInMemberID());

        $this->startFreshBrowser();
        $this->logInAs($this->getMember('admin'));
        $this->markSessionMFAVerified();
        $verified = $this->get('mfa-probe?archiveDate=' . urlencode($archiveDate));
        $this->assertSame(200, $verified->getStatusCode());
        $this->assertStringContainsString('Archived words', (string) $verified->getBody(), 'A verified member reads the archive');
    }

    /**
     * A protected (draft) file served through the asset store. A logged-in
     * member who can view the draft File is granted it; once the guard logs
     * an unverified member out, the request gets an anonymous visitor's
     * answer.
     */
    public function testAnUnverifiedMemberCannotReadAProtectedFile(): void
    {
        TestAssetStore::activate('MFASessionGuardMiddlewareTest');
        try
        {
            $file = File::create();
            $file->setFromString('mfa-protected-words', 'mfa-probe.txt');
            $file->write();
            $this->assertFalse($file->isPublished());
            $url = ltrim(Director::makeRelative($file->getURL(false)), '/');

            $this->startFreshBrowser();
            $anonymous = $this->get($url);
            $this->assertNotSame(200, $anonymous->getStatusCode(), 'Anonymous visitors cannot read the draft file');

            $this->startFreshBrowser();
            $this->logInAs($this->getMember('admin'));
            $response = $this->get($url);
            $this->assertStringNotContainsString('mfa-protected-words', (string) $response->getBody());
            $this->assertSame($anonymous->getStatusCode(), $response->getStatusCode(), 'The same answer an anonymous visitor gets');
            $this->assertNull($this->getLoggedInMemberID());

            $this->startFreshBrowser();
            $this->logInAs($this->getMember('admin'));
            $this->markSessionMFAVerified();
            $verified = $this->get($url);
            $this->assertSame(200, $verified->getStatusCode());
            $this->assertStringContainsString('mfa-protected-words', (string) $verified->getBody(), 'A verified member reads the draft file');
        }
        finally
        {
            TestAssetStore::reset();
        }
    }

    /**
     * The login, MFA, password and logout routes still work for a session the
     * guard has just ended: each answers once, with no redirect back to
     * itself.
     */
    public function testTheSecurityRoutesHaveNoRedirectLoop(): void
    {
        foreach (['Security/login', 'Security/login/default/mfa', 'Security/login/default/mfa/schema', 'Security/lostpassword', 'Security/changepassword', 'Security/logout'] as $url)
        {
            $this->startFreshBrowser();
            $this->logInAs($this->getMember('editor'));

            $response = $this->get($url);

            $this->assertNull($this->getLoggedInMemberID(), 'Logged out on /' . $url);
            $this->assertContains($response->getStatusCode(), [200, 302], '/' . $url);
            if ($response->getStatusCode() === 302)
            {
                $target = Director::makeRelative($this->getLocation($response));
                $this->assertNotSame($url, strtok($target, '?'), 'No loop on /' . $url);
                $followed = $this->get($target);
                $this->assertContains($followed->getStatusCode(), [200, 302], 'Followed from /' . $url);
            }
        }
    }

    public function testAMemberWithoutCMSAccessIsNotLoggedOut(): void
    {
        $public = $this->getMember('public');

        [$isDelegated] = $this->runGuard('admin/pages', $public);

        $this->assertTrue($isDelegated, 'Admin access is the CMS\'s own decision for this member');
        $this->assertSame((int) $public->ID, (int) Security::getCurrentUser()?->ID);
    }

    public function testNobodyLoggedInPassesThrough(): void
    {
        [$isDelegated] = $this->runGuard('admin/pages', null);

        $this->assertTrue($isDelegated);
    }

    public function testTheGuardStandsDownWhenMFAIsDisabled(): void
    {
        EnforcementManager::config()->set('enabled', false);
        $this->logInAs($this->getMember('admin'));

        $this->assertSame(200, $this->get('admin/pages')->getStatusCode());
    }

    /**
     * silverstripe-mfa#516: the framework logs a member in after a password
     * reset, and the module only asks for MFA there when the member has a
     * method. The guard sends the unenrolled member back to the login, which
     * then requires enrolment.
     */
    public function testAForgottenPasswordResetDoesNotReachTheCMS(): void
    {
        $editor = $this->getMember('editor');
        $this->get('Security/lostpassword');
        $this->submitForm('LostPasswordForm_lostPasswordForm', null, ['Email' => $editor->Email]);
        $email = $this->findEmail($editor->Email);
        $this->assertNotNull($email, 'The reset email is sent');
        $this->assertSame(1, preg_match('#Security/changepassword\?m=(\d+)(?:&amp;|&)t=([^"&\s<]+)#', (string) $email['HtmlContent'], $matches));

        $tokenRedirect = $this->get('Security/changepassword?m=' . $matches[1] . '&t=' . $matches[2]);
        $this->assertSame(302, $tokenRedirect->getStatusCode());
        $this->assertSame(200, $this->get(Director::makeRelative($this->getLocation($tokenRedirect)))->getStatusCode());
        $newPassword = 'Another-Correct-Horse-2026';
        $this->submitForm('ChangePasswordForm_ChangePasswordForm', null, $this->getChangePasswordFormData($newPassword));
        $this->assertSame((int) $editor->ID, $this->getLoggedInMemberID(), 'The framework logged the member in');
        $this->assertNull($this->getSessionMarker());

        $this->assertRefusedToLogin($this->get('admin/pages'), '/admin/pages');

        $this->assertRedirectsToMFA($this->submitPassword($editor->Email, $newPassword, '/admin/pages'));
        $schema = $this->getJSON(self::MFA_URL . '/schema');
        $this->assertEmpty($schema['registeredMethods'], 'The next step is registration');
        $this->assertFalse((bool) $schema['canSkip']);
    }

    public function testTheCMSReLoginPopupIsOff(): void
    {
        $this->assertFalse((bool) CMSSecurity::config()->get('reauth_enabled'));
        $this->assertFalse(CMSSecurity::singleton()->enabled());
    }

    public function testKeepMeSignedInIsOff(): void
    {
        $this->assertFalse(Security::config()->get('autologin_enabled'));

        $body = (string) $this->get('Security/login')->getBody();
        $this->assertStringNotContainsString('name="Remember"', $body);
    }
}
