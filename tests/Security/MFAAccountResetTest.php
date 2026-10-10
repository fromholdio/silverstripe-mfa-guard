<?php

namespace Fromholdio\MFAGuard\Tests\Security;

use Fromholdio\MFAGuard\Tests\Support\MFAFunctionalTestCase;
use SilverStripe\MFA\Model\RegisteredMethod;
use SilverStripe\Security\Member;

/**
 * The administrator-sent account reset: an MFA-verified administrator sends
 * it from Security, the member follows the emailed link, sets a new
 * password, loses their MFA methods, and is asked to enrol again at the next
 * sign-in. Nothing on the way logs them in.
 */
class MFAAccountResetTest extends MFAFunctionalTestCase
{
    protected static $fixture_file = 'MFATest.yml';

    public function testAnAdministratorResetLeadsBackToEnrollment(): void
    {
        $editor = $this->objFromFixture(Member::class, 'editor');
        $this->enroll($editor);
        $this->assertSame(2, RegisteredMethod::get()->filter('MemberID', $editor->ID)->count());

        $this->startFreshBrowser();
        $admin = $this->objFromFixture(Member::class, 'admin');
        $this->enroll($admin);
        $sent = $this->postJSON('admin/security/users/reset/' . $editor->ID, ['csrf_token' => 'disabled-in-tests']);
        $this->assertSame(200, $sent->getStatusCode(), (string) $sent->getBody());

        $email = $this->findEmail($editor->Email, null, 'Reset your account');
        $this->assertNotNull($email, 'The account reset email is sent to the member');
        $this->assertSame(1, preg_match('#Security/resetaccount\?m=(\d+)(?:&amp;|&)t=([^"&\s<]+)#', (string) $email['HtmlContent'], $matches));

        $this->startFreshBrowser();
        $page = $this->get('Security/resetaccount?m=' . $matches[1] . '&t=' . $matches[2]);
        $this->assertSame(200, $page->getStatusCode());
        $newPassword = 'Reset-Correct-Horse-2026';
        $reset = $this->submitForm('Form_ResetAccountForm', null, $this->getResetAccountFormData($newPassword));
        $this->assertSame(302, $reset->getStatusCode());
        $this->assertStringContainsString('Security/login', $this->getLocation($reset));
        $this->assertNull($this->getLoggedInMemberID(), 'The reset logs nobody in');
        $this->assertSame(0, RegisteredMethod::get()->filter('MemberID', $editor->ID)->count(), 'Every method removed');

        $this->assertRedirectsToMFA($this->submitPassword($editor->Email, $newPassword));
        $schema = $this->getJSON(self::MFA_URL . '/schema');
        $this->assertEmpty($schema['registeredMethods']);
        $this->assertFalse((bool) $schema['canSkip']);
    }

    public function testAnAdministratorWithoutMFACannotSendAReset(): void
    {
        $editor = $this->objFromFixture(Member::class, 'editor');
        $this->logInAs($this->objFromFixture(Member::class, 'admin'));

        $response = $this->postJSON('admin/security/users/reset/' . $editor->ID, ['csrf_token' => 'disabled-in-tests']);

        $this->assertSame(302, $response->getStatusCode());
        $this->assertNull($this->findEmail($editor->Email));
    }
}
