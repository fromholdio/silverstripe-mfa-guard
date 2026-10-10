<?php

namespace Fromholdio\MFAGuard\Tests\Support;

use SilverStripe\Security\Member;
use SilverStripe\SessionManager\Models\LoginSession;

/**
 * For MFAFunctionalTestCase tests that sign one member in on several browsers
 * and check which sessions survive a reset.
 *
 * A browser is the session data MFAFunctionalTestCase::saveBrowser()
 * returns. Each assertion restores that browser, makes its next request and
 * checks the outcome, so "logged out on its next request" is tested as a
 * real request through the whole middleware chain, LoginSessionMiddleware
 * included, rather than by reading the database alone.
 */
trait LoginSessionAssertions
{
    /**
     * How many LoginSession rows the member has: one per browser they are
     * signed in on.
     */
    protected function getLoginSessionCount(Member $member): int
    {
        return LoginSession::get()->filter('MemberID', (int) $member->ID)->count();
    }

    /**
     * Enrols the member in a fresh browser, which leaves them signed in
     * there. Returns the TOTP secret and that browser.
     *
     * @return array{0: string, 1: array}
     */
    protected function enrollOnNewBrowser(Member $member): array
    {
        $this->startFreshBrowser();
        $secret = (string) $this->enroll($member)['secret'];
        return [$secret, $this->saveBrowser()];
    }

    /**
     * Signs an enrolled member in, with password and a computed code, in a
     * fresh browser, and returns that browser.
     */
    protected function signInOnNewBrowser(Member $member, string $secret): array
    {
        $this->startFreshBrowser();
        $response = $this->signInWithCode($member->Email, 'totp', fn (): string => $this->getTotpCode($secret));
        $this->assertSame(200, $response->getStatusCode(), (string) $response->getBody());
        $this->assertSame((int) $member->ID, $this->getLoggedInMemberID());
        return $this->saveBrowser();
    }

    /**
     * The browser's next request reaches the CMS as the member. Returns the
     * browser as it stands after that request, to keep using it.
     */
    protected function assertBrowserSignedIn(array $browser, Member $member, string $message): array
    {
        $this->restoreBrowser($browser);
        $response = $this->get('admin/pages');
        $this->assertSame(200, $response->getStatusCode(), $message);
        $this->assertSame((int) $member->ID, $this->getLoggedInMemberID(), $message);
        return $this->saveBrowser();
    }

    /**
     * The browser's next request, to any URL, finds it logged out: nobody is
     * logged in and the MFA marker is gone with the session. A CMS request
     * from it then goes to the login.
     */
    protected function assertBrowserLoggedOut(array $browser, string $url, string $message): void
    {
        $this->restoreBrowser($browser);
        $this->assertNotNull($this->getLoggedInMemberID(), 'The browser was signed in before this request');

        $this->get($url);
        $this->assertNull($this->getLoggedInMemberID(), $message);
        $this->assertNull($this->getSessionMarker(), $message);

        $admin = $this->get('admin/pages');
        $this->assertSame(302, $admin->getStatusCode(), $message);
        $this->assertStringContainsString('Security/login', $this->getLocation($admin), $message);
    }
}
