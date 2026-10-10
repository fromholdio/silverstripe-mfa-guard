<?php

namespace Fromholdio\MFAGuard\Tests\Security;

use Fromholdio\MFAGuard\Extensions\AccountResetSessionExtension;
use Fromholdio\MFAGuard\Tests\Support\LoginSessionAssertions;
use Fromholdio\MFAGuard\Tests\Support\MFAFunctionalTestCase;
use SilverStripe\Control\Director;
use SilverStripe\Core\Config\Config;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\MFA\Extension\AccountReset\MFAResetExtension;
use SilverStripe\MFA\Extension\AccountReset\SecurityExtension;
use SilverStripe\MFA\Model\RegisteredMethod;
use SilverStripe\Security\Member;

/**
 * Completing an account reset ends every session the member had open, on
 * every device, and nothing short of that ends one.
 *
 * Each test holds several browsers at once: the member signed in on a
 * laptop and a phone, the administrator who sends the reset, and the browser
 * the reset is completed in. The module refuses the reset page to a
 * logged-in visitor, so the reset is always completed in a logged-out browser
 * of its own, as the member would after signing out or on a new phone.
 */
class MFAResetSessionsTest extends MFAFunctionalTestCase
{
    use LoginSessionAssertions;

    protected static $fixture_file = 'MFATest.yml';

    protected const NEW_PASSWORD = 'Reset-Correct-Horse-2026';


    /**
     * Helpers
     * ----------------------------------------------------
     */

    protected function getMember(string $identifier): Member
    {
        return $this->objFromFixture(Member::class, $identifier);
    }

    /**
     * The administrator signed in in the current browser sends the member an
     * account reset. Returns the emailed link's member ID and token.
     *
     * @return array{0: string, 1: string}
     */
    protected function sendAccountReset(Member $member): array
    {
        $sent = $this->postJSON('admin/security/users/reset/' . $member->ID, ['csrf_token' => 'disabled-in-tests']);
        $this->assertSame(200, $sent->getStatusCode(), (string) $sent->getBody());

        $email = $this->findEmail($member->Email, null, 'Reset your account');
        $this->assertNotNull($email, 'The account reset email is sent to the member');
        $this->assertSame(1, preg_match('#Security/resetaccount\?m=(\d+)(?:&amp;|&)t=([^"&\s<]+)#', (string) $email['HtmlContent'], $matches));
        return [$matches[1], $matches[2]];
    }

    /**
     * The member follows the emailed link in a fresh, logged-out browser and
     * sets a new password.
     *
     * @param array{0: string, 1: string} $link
     */
    protected function completeAccountReset(array $link): void
    {
        $this->startFreshBrowser();
        $page = $this->get('Security/resetaccount?m=' . $link[0] . '&t=' . $link[1]);
        $this->assertSame(200, $page->getStatusCode());

        $reset = $this->submitForm('Form_ResetAccountForm', null, $this->getResetAccountFormData(self::NEW_PASSWORD));
        $this->assertSame(302, $reset->getStatusCode());
        $this->assertStringContainsString('Security/login', $this->getLocation($reset));
        $this->assertNull($this->getLoggedInMemberID(), 'The reset logs nobody in');
    }


    /**
     * Tests
     * ----------------------------------------------------
     */

    /**
     * The mechanism: the extension sits on the module's handleAccountReset
     * hook after the module's own, and session-manager's middleware, which
     * logs out a session whose LoginSession row is gone, runs after the
     * framework has resolved the member.
     */
    public function testTheSessionEndingIsWired(): void
    {
        $extensions = array_values((array) Config::inst()->get(SecurityExtension::class, 'extensions'));
        $this->assertContains(AccountResetSessionExtension::class, $extensions);
        $this->assertGreaterThan(
            array_search(MFAResetExtension::class, $extensions),
            array_search(AccountResetSessionExtension::class, $extensions),
            'Sessions end after the module has removed the MFA methods'
        );

        $names = array_keys(Injector::inst()->get(Director::class)->getMiddlewares());
        $this->assertContains('LoginSessionMiddleware', $names);
        $this->assertLessThan(
            array_search('LoginSessionMiddleware', $names),
            array_search('AuthenticationMiddleware', $names),
            'AuthenticationMiddleware must run before (outside) LoginSessionMiddleware'
        );
    }

    public function testCompletingAnAccountResetEndsEverySessionTheMemberHad(): void
    {
        $editor = $this->getMember('editor');
        [$secret, $laptop] = $this->enrollOnNewBrowser($editor);
        $phone = $this->signInOnNewBrowser($editor, $secret);
        $this->assertSame(2, $this->getLoginSessionCount($editor), 'One session per browser');
        $laptop = $this->assertBrowserSignedIn($laptop, $editor, 'The laptop is signed in before the reset');
        $phone = $this->assertBrowserSignedIn($phone, $editor, 'The phone is signed in before the reset');

        $admin = $this->getMember('admin');
        $this->enrollOnNewBrowser($admin);
        $link = $this->sendAccountReset($editor);
        $adminBrowser = $this->saveBrowser();

        $this->completeAccountReset($link);

        $this->assertSame(0, $this->getLoginSessionCount($editor), 'Every LoginSession row of the member is gone');
        $this->assertSame(0, RegisteredMethod::get()->filter('MemberID', $editor->ID)->count(), 'Every method removed');
        $this->assertSame(1, $this->getLoginSessionCount($admin), 'The administrator\'s session is not touched');

        $this->assertBrowserLoggedOut($laptop, 'admin/pages', 'The laptop is logged out on its next CMS request');
        $this->assertBrowserLoggedOut($phone, 'Security/login', 'The phone is logged out on its next request, whatever the page');
        $this->assertBrowserSignedIn($adminBrowser, $admin, 'The administrator is still signed in');

        // After the reset the member's way back in is what it was: the new
        // password, then MFA registration with no skip, then the CMS. The new
        // session is not ended, however many requests follow.
        $this->startFreshBrowser();
        $this->assertRedirectsToMFA($this->submitPassword($editor->Email, self::NEW_PASSWORD));
        $schema = $this->getJSON(self::MFA_URL . '/schema');
        $this->assertEmpty($schema['registeredMethods']);
        $this->assertFalse((bool) $schema['canSkip']);

        $start = $this->startTotpRegistration();
        $newSecret = (string) $start['code'];
        $finish = $this->postJSON(self::MFA_URL . '/register/totp', ['code' => $this->getTotpCode($newSecret)]);
        $this->assertSame(201, $finish->getStatusCode(), (string) $finish->getBody());
        $this->getJSON(self::MFA_URL . '/register/backup-codes');
        $done = $this->postJSON(self::MFA_URL . '/register/backup-codes', []);
        $this->assertSame(201, $done->getStatusCode(), (string) $done->getBody());

        $this->assertSame(200, $this->get('admin/pages')->getStatusCode());
        $this->assertSame(200, $this->get('admin/pages')->getStatusCode());
        $this->assertSame((int) $editor->ID, $this->getSessionMarker());
        $this->assertSame(1, $this->getLoginSessionCount($editor), 'Only the session after the reset');
    }

    /**
     * Sending the email ends nothing: until the member completes the reset
     * their credentials are unchanged, so ending sessions then would only
     * make whoever holds those credentials sign in again.
     */
    public function testSendingAnAccountResetEndsNoSession(): void
    {
        $editor = $this->getMember('editor');
        [, $laptop] = $this->enrollOnNewBrowser($editor);

        $this->enrollOnNewBrowser($this->getMember('admin'));
        $this->sendAccountReset($editor);

        $this->assertSame(1, $this->getLoginSessionCount($editor));
        $this->assertBrowserSignedIn($laptop, $editor, 'The member is still signed in after the email is sent');
        $this->assertSame(2, RegisteredMethod::get()->filter('MemberID', $editor->ID)->count());
    }

    /**
     * With no reset of their own, a member's sessions carry on through
     * changes to their record and through another member's completed reset.
     */
    public function testSessionsSurviveUnrelatedChanges(): void
    {
        $editor = $this->getMember('editor');
        [$secret, $laptop] = $this->enrollOnNewBrowser($editor);
        $phone = $this->signInOnNewBrowser($editor, $secret);

        $other = $this->getMember('othereditor');
        [, $otherBrowser] = $this->enrollOnNewBrowser($other);

        $editor->FirstName = 'Casey-Renamed';
        $editor->write();

        $this->enrollOnNewBrowser($this->getMember('admin'));
        $this->completeAccountReset($this->sendAccountReset($other));

        $this->assertSame(0, $this->getLoginSessionCount($other), 'The other member\'s reset ended their session');
        $this->assertBrowserLoggedOut($otherBrowser, 'admin/pages', 'The other member is logged out');

        $this->assertSame(2, $this->getLoginSessionCount($editor));
        $this->assertBrowserSignedIn($laptop, $editor, 'The laptop is still signed in');
        $this->assertBrowserSignedIn($phone, $editor, 'The phone is still signed in');
    }
}
