<?php

namespace Fromholdio\MFAGuard\Tests\Support;

use SilverStripe\Control\HTTPRequest;
use SilverStripe\Control\HTTPResponse;
use SilverStripe\Control\Session;
use SilverStripe\Security\Member;

/**
 * DestroyedSessionMiddleware changes the emulated browser only when the
 * request's session was destroyed, and never otherwise: a session that
 * survives the request, empty or not, is left exactly as the framework
 * leaves it, and so is a session destroyed and then written again. The
 * functional controls run real requests through the whole chain, the
 * middleware included, and show that members the guard has no reason to
 * log out stay signed in from one request to the next, beside the same
 * request path for a member the guard does log out.
 */
class DestroyedSessionMiddlewareTest extends MFAFunctionalTestCase
{
    protected static $fixture_file = '../Security/MFATest.yml';


    /**
     * Helpers
     * ----------------------------------------------------
     */

    /**
     * Runs the middleware once around the given delegate with $_SESSION set
     * to the request's session data, as Director::test() sets it, and
     * returns whether $_SESSION was still set afterwards and its value. The
     * real $_SESSION is put back afterwards.
     *
     * @return array{0: bool, 1: mixed}
     */
    protected function runMiddleware(HTTPRequest $request, callable $delegate): array
    {
        $hadSession = isset($_SESSION);
        $original = $hadSession ? $_SESSION : null;
        $_SESSION = (array) $request->getSession()->getAll();
        try
        {
            DestroyedSessionMiddleware::create()->process($request, $delegate);
            return [isset($_SESSION), $_SESSION ?? null];
        }
        finally
        {
            unset($_SESSION);
            if ($hadSession)
            {
                $_SESSION = $original;
            }
        }
    }

    protected function createRequest(array $sessionData): HTTPRequest
    {
        $request = new HTTPRequest('GET', 'admin/pages');
        $request->setSession(new Session($sessionData));
        return $request;
    }


    /**
     * Tests
     * ----------------------------------------------------
     */

    public function testASurvivingSessionIsLeftAsItIs(): void
    {
        $request = $this->createRequest(['loggedInAs' => 7]);

        [$isSet, $value] = $this->runMiddleware($request, function (HTTPRequest $request): HTTPResponse
        {
            $request->getSession()->set('Message', 'written during the request');
            $_SESSION['Message'] = 'written during the request';
            return HTTPResponse::create('ok');
        });

        $this->assertTrue($isSet);
        $this->assertSame(['loggedInAs' => 7, 'Message' => 'written during the request'], $value, 'Nothing is removed or added');
    }

    public function testAnEmptySurvivingSessionIsLeftAsItIs(): void
    {
        $request = $this->createRequest([]);

        [$isSet, $value] = $this->runMiddleware($request, fn (HTTPRequest $request): HTTPResponse => HTTPResponse::create('ok'));

        $this->assertTrue($isSet);
        $this->assertSame([], $value);
    }

    public function testADestroyedSessionIsLost(): void
    {
        $request = $this->createRequest(['loggedInAs' => 7, 'MFAGuardVerifiedMemberID' => 7]);

        [$isSet, $value] = $this->runMiddleware($request, function (HTTPRequest $request): HTTPResponse
        {
            $request->getSession()->destroy(false, $request);
            return HTTPResponse::create('ok');
        });

        $this->assertTrue($isSet);
        $this->assertSame([], $value, 'The emulated browser keeps nothing of a destroyed session');
    }

    /**
     * Values written after the destroy are what a real browser carries in
     * the fresh session the framework starts for them; nothing from before
     * the destroy comes back.
     */
    public function testOnlyWritesAfterADestroyAreKept(): void
    {
        $request = $this->createRequest(['loggedInAs' => 7, 'activeLoginSession' => 3]);

        [$isSet, $value] = $this->runMiddleware($request, function (HTTPRequest $request): HTTPResponse
        {
            $request->getSession()->destroy(false, $request);
            $request->getSession()->clear('activeLoginSession');
            $request->getSession()->set('Message', 'written after the log-out');
            return HTTPResponse::create('ok');
        });

        $this->assertTrue($isSet);
        $this->assertArrayNotHasKey('loggedInAs', (array) $value);
        $this->assertNull($value['activeLoginSession'] ?? null);
        $this->assertSame('written after the log-out', $value['Message'] ?? null);
    }

    /**
     * The control for the guard tests: a verified CMS member and a member
     * MFA does not apply to stay signed in, with the middleware in place,
     * across requests to the CMS and to Security routes, while an unverified
     * CMS member making the same first request is logged out and stays out.
     */
    public function testOnlyTheMemberTheGuardLogsOutIsSignedOut(): void
    {
        $editor = $this->objFromFixture(Member::class, 'editor');
        $this->logInAs($editor);
        $this->markSessionMFAVerified();
        $this->assertSame(200, $this->get('admin/pages')->getStatusCode());
        $this->get('Security/lostpassword');
        $this->assertSame(200, $this->get('admin/pages')->getStatusCode());
        $this->assertSame((int) $editor->ID, $this->getLoggedInMemberID(), 'The verified member stays signed in');
        $this->assertSame((int) $editor->ID, $this->getSessionMarker(), 'With their marker');

        $this->startFreshBrowser();
        $public = $this->objFromFixture(Member::class, 'public');
        $this->logInAs($public);
        $this->get('admin/pages');
        $this->get('Security/lostpassword');
        $this->assertSame((int) $public->ID, $this->getLoggedInMemberID(), 'A member MFA does not apply to stays signed in');

        $this->startFreshBrowser();
        $this->logInAs($editor);
        $this->assertSame(302, $this->get('admin/pages')->getStatusCode());
        $this->assertNull($this->getLoggedInMemberID(), 'The unverified member is signed out');
        $this->get('Security/lostpassword');
        $this->assertNull($this->getLoggedInMemberID(), 'And stays signed out');
    }
}
