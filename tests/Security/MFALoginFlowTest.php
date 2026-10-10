<?php

namespace Fromholdio\MFAGuard\Tests\Security;

use Fromholdio\MFAGuard\Authenticators\MFALoginHandler;
use Fromholdio\MFAGuard\Tests\Support\MFAFunctionalTestCase;
use SilverStripe\MFA\Authenticator\MemberAuthenticator;
use SilverStripe\MFA\Model\RegisteredMethod;
use SilverStripe\Security\LoginAttempt;
use SilverStripe\Security\Member;

/**
 * The CMS login end to end, through the module's real endpoints: the
 * password alone never reaches the CMS; registration and each verification
 * route end logged in with the session marker; a wrong code is refused and
 * counted once; a backup code works once; a wrong password counts once.
 */
class MFALoginFlowTest extends MFAFunctionalTestCase
{
    protected static $fixture_file = 'MFATest.yml';

    protected function getMember(string $fixture): Member
    {
        return $this->objFromFixture(Member::class, $fixture);
    }

    protected function getLoginAttemptCount(Member $member, string $status): int
    {
        return LoginAttempt::get()->filter(['MemberID' => $member->ID, 'Status' => $status])->count();
    }

    protected function reloadMember(Member $member): Member
    {
        return Member::get()->byID($member->ID);
    }


    /**
     * Tests
     * ----------------------------------------------------
     */

    public function testTheInjectorResolvesTheLoginHandler(): void
    {
        $handler = (new MemberAuthenticator())->getLoginHandler('Security/login/default');

        $this->assertSame(MFALoginHandler::class, get_class($handler));
    }

    public function testThePasswordStepAloneDoesNotReachTheCMS(): void
    {
        $editor = $this->getMember('editor');

        $response = $this->submitPassword($editor->Email);

        $this->assertRedirectsToMFA($response);
        $this->assertNull($this->getLoggedInMemberID(), 'Nobody is logged in after the password step');
        $this->assertNull($this->getSessionMarker());

        $admin = $this->get('admin/pages');
        $this->assertSame(302, $admin->getStatusCode());
        $this->assertStringContainsString('Security/login', $this->getLocation($admin));
    }

    public function testTheMFAScreenOffersNoSkip(): void
    {
        $this->assertRedirectsToMFA($this->submitPassword($this->getMember('editor')->Email));

        $schema = $this->getJSON(self::MFA_URL . '/schema');
        $this->assertFalse((bool) $schema['canSkip']);

        $skip = $this->get(self::MFA_URL . '/skip');
        $this->assertSame(302, $skip->getStatusCode());
        $this->assertNull($this->getLoggedInMemberID());
    }

    public function testRegistrationEndsLoggedInWithTheMarkerAndReachesTheCMS(): void
    {
        $editor = $this->getMember('editor');

        $this->enroll($editor, '/admin/pages');

        $this->assertSame((int) $editor->ID, $this->getLoggedInMemberID());
        $this->assertSame((int) $editor->ID, $this->getSessionMarker());
        $this->assertSame(2, RegisteredMethod::get()->filter('MemberID', $editor->ID)->count(), 'TOTP and backup codes');

        $complete = $this->get(self::MFA_URL . '/complete');
        $this->assertSame(302, $complete->getStatusCode());
        $this->assertStringEndsWith('/admin/pages', $this->getLocation($complete));

        $this->assertSame(200, $this->get('admin/pages')->getStatusCode());
    }

    public function testAWrongRegistrationCodeRegistersNothing(): void
    {
        $editor = $this->getMember('editor');
        $this->assertRedirectsToMFA($this->submitPassword($editor->Email));
        $secret = (string) $this->startTotpRegistration()['code'];

        $response = $this->postJSON(self::MFA_URL . '/register/totp', ['code' => $this->getWrongTotpCode($secret)]);

        $this->assertSame(400, $response->getStatusCode());
        $this->assertSame(0, RegisteredMethod::get()->filter('MemberID', $editor->ID)->count());
        $this->assertNull($this->getLoggedInMemberID());
    }

    public function testASecondSignInPassesWithAComputedCode(): void
    {
        $editor = $this->getMember('editor');
        $secret = $this->enroll($editor)['secret'];
        $this->startFreshBrowser();

        $response = $this->signInWithCode($editor->Email, 'totp', fn (): string => $this->getTotpCode($secret));

        $this->assertSame(200, $response->getStatusCode(), (string) $response->getBody());
        $this->assertSame((int) $editor->ID, $this->getLoggedInMemberID());
        $this->assertSame((int) $editor->ID, $this->getSessionMarker());
        $this->assertSame(200, $this->get('admin/pages')->getStatusCode());
    }

    /**
     * The module counts a wrong code in FailedLoginCount, the same tally a
     * wrong password feeds; it records no LoginAttempt, which is only written
     * by the password check.
     */
    public function testAWrongCodeIsRefusedAndCountedOnce(): void
    {
        $editor = $this->getMember('editor');
        $secret = $this->enroll($editor)['secret'];
        $this->startFreshBrowser();
        $failedBefore = (int) $this->reloadMember($editor)->FailedLoginCount;
        $attemptsBefore = $this->getLoginAttemptCount($editor, LoginAttempt::FAILURE);

        $response = $this->signInWithCode($editor->Email, 'totp', fn (): string => $this->getWrongTotpCode($secret));

        $this->assertSame(401, $response->getStatusCode());
        $this->assertSame($failedBefore + 1, (int) $this->reloadMember($editor)->FailedLoginCount);
        $this->assertSame($attemptsBefore, $this->getLoginAttemptCount($editor, LoginAttempt::FAILURE));
        $this->assertNull($this->getLoggedInMemberID());
        $this->assertNull($this->getSessionMarker());
    }

    public function testRepeatedWrongCodesLockTheAccount(): void
    {
        $editor = $this->getMember('editor');
        $secret = $this->enroll($editor)['secret'];
        $this->startFreshBrowser();
        $this->assertRedirectsToMFA($this->submitPassword($editor->Email));
        $this->getJSON(self::MFA_URL . '/verify/totp');
        $limit = (int) Member::config()->get('lock_out_after_incorrect_logins');
        $wrong = $this->getWrongTotpCode($secret);

        for ($i = 0; $i < $limit; $i++)
        {
            $this->assertSame(401, $this->postJSON(self::MFA_URL . '/verify/totp', ['code' => $wrong])->getStatusCode());
        }
        $this->assertTrue($this->reloadMember($editor)->isLockedOut());

        $locked = $this->postJSON(self::MFA_URL . '/verify/totp', ['code' => $this->getTotpCode($secret)]);
        $this->assertSame(403, $locked->getStatusCode());
        $this->assertStringContainsString('temporarily locked', (string) $locked->getBody());
        $this->assertNull($this->getLoggedInMemberID());
    }

    public function testABackupCodeWorksOnceOnly(): void
    {
        $editor = $this->getMember('editor');
        $codes = $this->enroll($editor)['backupCodes'];
        $this->startFreshBrowser();

        $first = $this->signInWithCode($editor->Email, 'backup-codes', (string) $codes[0]);
        $this->assertSame(200, $first->getStatusCode(), (string) $first->getBody());
        $this->assertSame((int) $editor->ID, $this->getSessionMarker());
        $this->assertSame(200, $this->get('admin/pages')->getStatusCode());

        $this->startFreshBrowser();
        $again = $this->signInWithCode($editor->Email, 'backup-codes', (string) $codes[0]);
        $this->assertSame(401, $again->getStatusCode());
        $this->assertNull($this->getLoggedInMemberID());

        $this->startFreshBrowser();
        $next = $this->signInWithCode($editor->Email, 'backup-codes', (string) $codes[1]);
        $this->assertSame(200, $next->getStatusCode());
    }

    /**
     * silverstripe-mfa#421: without the single-check handler each wrong
     * password recorded two failed attempts.
     */
    public function testOneWrongPasswordIsCountedOnce(): void
    {
        $editor = $this->getMember('editor');

        $response = $this->submitPassword($editor->Email, 'not-the-password');

        $this->assertSame(302, $response->getStatusCode());
        $this->assertStringNotContainsString('mfa', $this->getLocation($response));
        $this->assertSame(1, $this->getLoginAttemptCount($editor, LoginAttempt::FAILURE));
        $this->assertSame(1, (int) $this->reloadMember($editor)->FailedLoginCount);
    }

    /**
     * The other path through the framework's doLogin(): a member MFA does not
     * apply to logs in with one recorded attempt and no marker.
     */
    public function testAMemberWithoutCMSAccessLogsInWithOneCheckAndNoMFA(): void
    {
        $public = $this->getMember('public');

        $response = $this->submitPassword($public->Email);

        $this->assertSame(302, $response->getStatusCode());
        $this->assertStringNotContainsString('mfa', $this->getLocation($response));
        $this->assertSame((int) $public->ID, $this->getLoggedInMemberID());
        $this->assertNull($this->getSessionMarker());
        $this->assertSame(1, $this->getLoginAttemptCount($public, LoginAttempt::SUCCESS));
    }
}
