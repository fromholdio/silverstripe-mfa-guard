<?php

namespace Fromholdio\MFAGuard\Tests\Security;

use Closure;
use Fromholdio\MFAGuard\Authenticators\MFAChangePasswordHandler;
use Fromholdio\MFAGuard\Tests\Support\MFAFunctionalTestCase;
use ReflectionProperty;
use SilverStripe\Control\Director;
use SilverStripe\Control\HTTPResponse;
use SilverStripe\MFA\Authenticator\ChangePasswordHandler;
use SilverStripe\MFA\Authenticator\MemberAuthenticator;
use SilverStripe\MFA\Model\RegisteredMethod;
use SilverStripe\MFA\Service\EnforcementManager;
use SilverStripe\MFA\Store\SessionStore;
use SilverStripe\ORM\FieldType\DBDatetime;
use SilverStripe\Security\Member;
use SilverStripe\Security\MemberAuthenticator\ChangePasswordHandler as FrameworkChangePasswordHandler;
use SilverStripe\Security\Validation\EntropyPasswordValidator;

/**
 * A forgotten-password reset, end to end through the real endpoints: the
 * "I've lost my password" form, the emailed link, the module's code prompt
 * under Security/changepassword/mfa, the new-password form, and the CMS.
 *
 * - An enrolled member enters one code (authenticator or recovery code) and
 *   lands logged in with the session marker, so the CMS answers at once.
 * - That code counts only for the member and the reset it was entered for:
 *   a code passed for another account, for the same account in an earlier
 *   reset, or by swapping the module's MFA store at the login, never shows
 *   the form, changes the password or logs anyone in.
 * - The new password cannot be posted without the code, and wrong codes on
 *   the reset prompt count towards the lockout as they do at the login.
 * - An unenrolled member's reset still ends at the login and enrolment
 *   (silverstripe-mfa#516), and a logged-in member still changes their own
 *   password with their current one.
 */
class MFAChangePasswordHandlerTest extends MFAFunctionalTestCase
{
    protected static $fixture_file = 'MFATest.yml';

    protected const NEW_PASSWORD = 'Another-Correct-Horse-2026';

    protected const CHANGE_PASSWORD_URL = 'Security/changepassword';

    protected const RESET_MFA_URL = 'Security/changepassword/mfa';

    protected function setUp(): void
    {
        parent::setUp();
        $this->resetChangePasswordRequestState();
    }

    protected function tearDown(): void
    {
        $this->resetChangePasswordRequestState();
        parent::tearDown();
    }


    /**
     * Helpers
     * ----------------------------------------------------
     */

    protected function getMember(string $fixture): Member
    {
        return $this->objFromFixture(Member::class, $fixture);
    }

    protected function reloadMember(Member $member): Member
    {
        return Member::get()->byID($member->ID);
    }

    /**
     * The framework's change-password handler remembers, in two private
     * statics, that it has issued or consumed a temporary hash "during this
     * request cycle". Each browser request is a new PHP process; a
     * functional test's are not, so the flags are cleared before every
     * emulated link visit, as silverstripe/mfa's own ChangePasswordHandlerTest
     * does, and after each test so no other test inherits them.
     */
    protected function resetChangePasswordRequestState(): void
    {
        foreach (['tempHashAlreadyGenerated', 'tempHashAlreadyProcessed'] as $property)
        {
            $reflection = new ReflectionProperty(FrameworkChangePasswordHandler::class, $property);
            $reflection->setValue(null, false);
        }
    }

    /**
     * "I've lost my password" for this member; returns the emailed link as a
     * relative URL.
     */
    protected function requestResetLink(Member $member): string
    {
        $this->clearEmails();
        $this->get('Security/lostpassword');
        $this->submitForm('LostPasswordForm_lostPasswordForm', null, ['Email' => $member->Email]);
        $email = $this->findEmail($member->Email);
        $this->assertNotNull($email, 'The reset email is sent');
        $this->assertSame(
            1,
            preg_match('#Security/changepassword\?m=(\d+)(?:&amp;|&)t=([^"&\s<]+)#', (string) $email['HtmlContent'], $matches),
            'The email carries a reset link'
        );
        return self::CHANGE_PASSWORD_URL . '?m=' . $matches[1] . '&t=' . $matches[2];
    }

    /**
     * Follows the emailed link as a browser does: the token URL redirects to
     * a temporary-hash URL, which puts the reset into the session and
     * renders either the code prompt or the new-password form.
     */
    protected function openResetLink(string $link): HTTPResponse
    {
        $this->resetChangePasswordRequestState();
        $redirect = $this->get($link);
        $this->assertSame(302, $redirect->getStatusCode(), 'The token URL redirects to the temporary hash');
        $this->resetChangePasswordRequestState();
        $response = $this->get(Director::makeRelative($this->getLocation($redirect)));
        $this->assertSame(200, $response->getStatusCode());
        return $response;
    }

    /**
     * Starts the code prompt for a method, then posts one code, as the
     * module's React app does. A time-based code is passed as a closure so
     * it is computed just before the post.
     */
    protected function submitResetCode(string $segment, string|Closure $code): HTTPResponse
    {
        $this->getJSON(self::RESET_MFA_URL . '/login/' . $segment);
        $value = $code instanceof Closure ? $code() : $code;
        return $this->postJSON(self::RESET_MFA_URL . '/login/' . $segment, ['code' => $value]);
    }

    /**
     * Loads the change-password page and submits its new-password form.
     */
    protected function submitNewPassword(string $password = self::NEW_PASSWORD): HTTPResponse
    {
        $this->assertShowsPasswordForm($this->get(self::CHANGE_PASSWORD_URL));
        return $this->submitForm(
            'ChangePasswordForm_ChangePasswordForm',
            null,
            $this->getChangePasswordFormData($password)
        );
    }

    /**
     * Posts a new password straight to the form's action, without loading
     * the page that would have shown the code prompt.
     */
    protected function postNewPasswordDirectly(string $password = self::NEW_PASSWORD): HTTPResponse
    {
        return $this->post(
            self::CHANGE_PASSWORD_URL . '/ChangePasswordForm',
            $this->getChangePasswordPostData($password) + ['action_doChangePassword' => 1]
        );
    }

    /**
     * The code prompt is showing, for this member, and the form is not.
     */
    protected function assertAsksForCodeFrom(Member $member, HTTPResponse $response): void
    {
        $body = (string) $response->getBody();
        $this->assertStringContainsString('id="mfa-app"', $body, 'The code prompt is shown');
        $this->assertStringNotContainsString($this->getNewPasswordFieldName(), $body, 'The new-password form is not shown');
        $store = $this->session()->get(SessionStore::SESSION_KEY);
        $this->assertInstanceOf(SessionStore::class, $store);
        $this->assertSame((int) $member->ID, (int) $store->getMember()->ID, 'The code is asked of this member');
    }

    protected function assertShowsPasswordForm(HTTPResponse $response): void
    {
        $body = (string) $response->getBody();
        $this->assertStringContainsString($this->getNewPasswordFieldName(), $body, 'The new-password form is shown');
        $this->assertStringNotContainsString('id="mfa-app"', $body, 'The code prompt is not shown');
    }

    /**
     * Nothing came of the attempt: the password is the one it was, nobody is
     * logged in, there is no marker, and the CMS sends the visitor to the
     * login.
     */
    protected function assertNothingChanged(Member $member, string $passwordHash): void
    {
        $this->assertSame($passwordHash, (string) $this->reloadMember($member)->Password, 'The password is unchanged');
        $this->assertNull($this->getLoggedInMemberID(), 'Nobody is logged in');
        $this->assertNull($this->getSessionMarker(), 'There is no MFA marker');
        $admin = $this->get('admin/pages');
        $this->assertSame(302, $admin->getStatusCode());
        $this->assertStringContainsString('Security/login', $this->getLocation($admin));
    }

    /**
     * A new password was refused after a successful code on a live reset:
     * the browser is sent back to the form, nothing changed and nobody is
     * logged in, but the reset and its verification are kept, so the form
     * reloads with the refusal message and no second code prompt.
     */
    protected function assertRetryKeepsTheVerification(Member $member, string $passwordHash, HTTPResponse $refused, string $message): void
    {
        $this->assertSame(302, $refused->getStatusCode());
        $this->assertStringContainsString(self::CHANGE_PASSWORD_URL, $this->getLocation($refused), 'Back to the form');
        $this->assertSame($passwordHash, (string) $this->reloadMember($member)->Password, 'The password is unchanged');
        $this->assertNull($this->getLoggedInMemberID(), 'Nobody is logged in');
        $this->assertNull($this->getSessionMarker(), 'There is no MFA marker');
        $this->assertNotNull($this->session()->get(MFAChangePasswordHandler::SESSION_AUTO_LOGIN_HASH), 'The reset is still live');
        $this->assertNotNull($this->session()->get(MFAChangePasswordHandler::SESSION_VERIFIED_RESET), 'The verification is kept');

        $form = $this->get(Director::makeRelative($this->getLocation($refused)));
        $this->assertShowsPasswordForm($form);
        $this->assertStringContainsString($message, html_entity_decode((string) $form->getBody(), ENT_QUOTES));
    }

    /**
     * The reset ended logged in as this member with the marker, without a
     * second sign-in, and the CMS answers.
     */
    protected function assertLandsInTheCMSAs(Member $member, HTTPResponse $changed): void
    {
        $this->assertSame(302, $changed->getStatusCode());
        $this->assertStringNotContainsString('mfa', $this->getLocation($changed), 'No second code step');
        $this->assertSame((int) $member->ID, $this->getLoggedInMemberID(), 'Logged in by the reset');
        $this->assertSame((int) $member->ID, $this->getSessionMarker(), 'With the MFA marker for this member');
        $this->assertNull($this->session()->get(MFAChangePasswordHandler::SESSION_VERIFIED_RESET), 'The verification is used up');
        $this->assertNull($this->session()->get(ChangePasswordHandler::MFA_VERIFIED_ON_CHANGE_PASSWORD), 'The module flag is cleared');

        $landing = $this->get(Director::makeRelative($this->getLocation($changed)));
        $this->assertSame(200, $landing->getStatusCode());
        $this->assertSame((int) $member->ID, $this->getLoggedInMemberID(), 'Still logged in on the landing page');
        $this->assertSame(200, $this->get('admin/pages')->getStatusCode());
        $this->assertNull($this->reloadMember($member)->AutoLoginHash, 'The reset link is spent');
    }


    /**
     * Tests
     * ----------------------------------------------------
     */

    public function testTheInjectorResolvesTheChangePasswordHandler(): void
    {
        $handler = (new MemberAuthenticator())->getChangePasswordHandler(self::CHANGE_PASSWORD_URL);

        $this->assertSame(MFAChangePasswordHandler::class, get_class($handler));
    }

    public function testAnEnrolledResetAsksForOneAuthenticatorCodeAndEndsInTheCMS(): void
    {
        $editor = $this->getMember('editor');
        $secret = $this->enroll($editor)['secret'];
        $this->startFreshBrowser();

        $this->assertAsksForCodeFrom($editor, $this->openResetLink($this->requestResetLink($editor)));
        $verified = $this->submitResetCode('totp', fn (): string => $this->getTotpCode($secret));
        $this->assertSame(200, $verified->getStatusCode(), (string) $verified->getBody());
        $this->assertNull($this->getLoggedInMemberID(), 'The code alone logs nobody in');

        $this->assertLandsInTheCMSAs($editor, $this->submitNewPassword());
    }

    public function testAnEnrolledResetWorksWithARecoveryCode(): void
    {
        $editor = $this->getMember('editor');
        $codes = $this->enroll($editor)['backupCodes'];
        $this->startFreshBrowser();

        $this->assertAsksForCodeFrom($editor, $this->openResetLink($this->requestResetLink($editor)));
        $verified = $this->submitResetCode('backup-codes', (string) $codes[0]);
        $this->assertSame(200, $verified->getStatusCode(), (string) $verified->getBody());

        $this->assertLandsInTheCMSAs($editor, $this->submitNewPassword());
    }

    /**
     * The replay the module's bare boolean allows: someone passes MFA for
     * their own account during its reset, then opens another member's reset
     * link (from that member's compromised mailbox) in the same browser.
     */
    public function testACodeForOneMembersResetDoesNotUnlockAnothers(): void
    {
        $victim = $this->getMember('editor');
        $attacker = $this->getMember('othereditor');
        $this->enroll($victim);
        $this->startFreshBrowser();
        $attackerSecret = $this->enroll($attacker)['secret'];
        $this->startFreshBrowser();
        $victimLink = $this->requestResetLink($victim);
        $victimPassword = (string) $this->reloadMember($victim)->Password;

        $this->assertAsksForCodeFrom($attacker, $this->openResetLink($this->requestResetLink($attacker)));
        $verified = $this->submitResetCode('totp', fn (): string => $this->getTotpCode($attackerSecret));
        $this->assertSame(200, $verified->getStatusCode(), 'The attacker passes MFA for their own reset');

        $this->assertAsksForCodeFrom($victim, $this->openResetLink($victimLink));
        $this->assertNull($this->session()->get(MFAChangePasswordHandler::SESSION_VERIFIED_RESET), "The attacker's record is forgotten");
        $this->assertAsksForCodeFrom($victim, $this->get(self::CHANGE_PASSWORD_URL));
        $this->postNewPasswordDirectly();
        $this->assertNothingChanged($victim, $victimPassword);

        $this->assertAsksForCodeFrom($victim, $this->openResetLink($victimLink));
        $wrong = $this->submitResetCode('totp', fn (): string => $this->getTotpCode($attackerSecret));
        $this->assertSame(401, $wrong->getStatusCode(), "The attacker's code is refused for the victim");
        $this->assertNothingChanged($victim, $victimPassword);
    }

    /**
     * The module's MFA store is shared with the login. With another member's
     * reset in the session, a password step at the login points the store at
     * the attacker's own account, whose code the reset prompt then accepts.
     */
    public function testACodeForASwappedStoreDoesNotVerifyTheReset(): void
    {
        $victim = $this->getMember('editor');
        $attacker = $this->getMember('othereditor');
        $this->enroll($victim);
        $this->startFreshBrowser();
        $attackerSecret = $this->enroll($attacker)['secret'];
        $this->startFreshBrowser();
        $victimLink = $this->requestResetLink($victim);
        $victimPassword = (string) $this->reloadMember($victim)->Password;

        $this->assertAsksForCodeFrom($victim, $this->openResetLink($victimLink));
        $this->assertRedirectsToMFA($this->submitPassword($attacker->Email));
        $swapped = $this->submitResetCode('totp', fn (): string => $this->getTotpCode($attackerSecret));
        $this->assertSame(403, $swapped->getStatusCode(), 'A code for someone other than the reset member is refused');
        $this->assertNull($this->session()->get(ChangePasswordHandler::MFA_VERIFIED_ON_CHANGE_PASSWORD));

        $this->assertAsksForCodeFrom($victim, $this->get(self::CHANGE_PASSWORD_URL));
        $this->postNewPasswordDirectly();
        $this->assertNothingChanged($victim, $victimPassword);
    }

    /**
     * A code passed during one reset that was never finished does not carry
     * over to a later reset of the same account: the later link asks again.
     */
    public function testACodeFromAnEarlierResetDoesNotCarryOver(): void
    {
        $editor = $this->getMember('editor');
        $secret = $this->enroll($editor)['secret'];
        $this->startFreshBrowser();

        $this->assertAsksForCodeFrom($editor, $this->openResetLink($this->requestResetLink($editor)));
        $this->assertSame(200, $this->submitResetCode('totp', fn (): string => $this->getTotpCode($secret))->getStatusCode());

        $laterLink = $this->requestResetLink($editor);
        $this->assertAsksForCodeFrom($editor, $this->openResetLink($laterLink));
        $this->assertAsksForCodeFrom($editor, $this->get(self::CHANGE_PASSWORD_URL));

        $verified = $this->submitResetCode('totp', fn (): string => $this->getTotpCode($secret));
        $this->assertSame(200, $verified->getStatusCode(), (string) $verified->getBody());
        $this->assertLandsInTheCMSAs($editor, $this->submitNewPassword());
    }

    /**
     * A member who registered an authenticator app but stopped before saving
     * their recovery codes has not finished enrolling. A reset with their
     * code changes the password but grants no marker, as the login grants
     * none until registration is complete; their next sign-in has them
     * finish it before the CMS opens.
     */
    public function testAnInterruptedEnrollmentStillHasToFinishAfterAReset(): void
    {
        $editor = $this->getMember('editor');
        $this->assertRedirectsToMFA($this->submitPassword($editor->Email));
        $secret = (string) $this->startTotpRegistration()['code'];
        $registered = $this->postJSON(self::MFA_URL . '/register/totp', ['code' => $this->getTotpCode($secret)]);
        $this->assertSame(201, $registered->getStatusCode(), (string) $registered->getBody());
        $this->assertSame(1, RegisteredMethod::get()->filter('MemberID', $editor->ID)->count(), 'The app only, no recovery codes');
        $this->assertFalse(EnforcementManager::create()->hasCompletedRegistration($this->reloadMember($editor)));
        $this->assertNull($this->getLoggedInMemberID(), 'An unfinished enrolment logs nobody in');
        $this->startFreshBrowser();
        $password = (string) $this->reloadMember($editor)->Password;

        $this->assertAsksForCodeFrom($editor, $this->openResetLink($this->requestResetLink($editor)));
        $verified = $this->submitResetCode('totp', fn (): string => $this->getTotpCode($secret));
        $this->assertSame(200, $verified->getStatusCode(), (string) $verified->getBody());
        $changed = $this->submitNewPassword();

        $this->assertSame(302, $changed->getStatusCode());
        $this->assertNotSame($password, (string) $this->reloadMember($editor)->Password, 'The password changed');
        $this->assertSame((int) $editor->ID, $this->getLoggedInMemberID(), 'The framework logged the member in');
        $this->assertNull($this->getSessionMarker(), 'Without the marker: enrolment is unfinished');
        $this->assertNull($this->session()->get(MFAChangePasswordHandler::SESSION_VERIFIED_RESET), 'The verification is used up');
        $admin = $this->get('admin/pages');
        $this->assertSame(302, $admin->getStatusCode());
        $this->assertStringContainsString('Security/login', $this->getLocation($admin));
        $this->assertNull($this->getLoggedInMemberID(), 'The guard logged them out');

        $this->assertRedirectsToMFA($this->submitPassword($editor->Email, self::NEW_PASSWORD, '/admin/pages'));
        $this->getJSON(self::MFA_URL . '/verify/totp');
        $signedIn = $this->postJSON(self::MFA_URL . '/verify/totp', ['code' => $this->getTotpCode($secret)]);
        $this->assertSame(200, $signedIn->getStatusCode(), (string) $signedIn->getBody());
        $this->assertNull($this->getLoggedInMemberID(), 'The code alone does not finish an unfinished enrolment');
        $this->assertNull($this->getSessionMarker());

        $backup = $this->getJSON(self::MFA_URL . '/register/backup-codes');
        $this->assertNotEmpty($backup['codes'] ?? [], 'The recovery codes are the remaining step');
        $finished = $this->postJSON(self::MFA_URL . '/register/backup-codes', []);
        $this->assertSame(201, $finished->getStatusCode(), (string) $finished->getBody());
        $this->assertTrue(EnforcementManager::create()->hasCompletedRegistration($this->reloadMember($editor)));
        $this->assertSame((int) $editor->ID, $this->getLoggedInMemberID());
        $this->assertSame((int) $editor->ID, $this->getSessionMarker());
        $this->assertSame(200, $this->get('admin/pages')->getStatusCode());
    }

    /**
     * A verification ends with its reset. If the link expires between the
     * code and the new password, the framework refuses the password and
     * drops the reset, and the verification and the module's flag go too.
     */
    public function testAnExpiredResetForgetsItsVerification(): void
    {
        $editor = $this->getMember('editor');
        $secret = $this->enroll($editor)['secret'];
        $this->startFreshBrowser();
        $this->assertAsksForCodeFrom($editor, $this->openResetLink($this->requestResetLink($editor)));
        $this->assertSame(200, $this->submitResetCode('totp', fn (): string => $this->getTotpCode($secret))->getStatusCode());
        $this->assertNotNull($this->session()->get(MFAChangePasswordHandler::SESSION_VERIFIED_RESET));
        $this->assertTrue((bool) $this->session()->get(ChangePasswordHandler::MFA_VERIFIED_ON_CHANGE_PASSWORD));
        $password = (string) $this->reloadMember($editor)->Password;

        $expiring = $this->reloadMember($editor);
        $expiring->AutoLoginExpired = date('Y-m-d H:i:s', DBDatetime::now()->getTimestamp() - 60);
        $expiring->write();
        $this->postNewPasswordDirectly();

        $this->assertNull($this->session()->get(MFAChangePasswordHandler::SESSION_AUTO_LOGIN_HASH), 'The framework dropped the reset');
        $this->assertNull($this->session()->get(MFAChangePasswordHandler::SESSION_VERIFIED_RESET), 'The verification is forgotten');
        $this->assertNull($this->session()->get(ChangePasswordHandler::MFA_VERIFIED_ON_CHANGE_PASSWORD), 'The module flag is cleared');
        $this->assertNothingChanged($editor, $password);
    }

    /**
     * The same when a new reset replaces the hash this session holds: the
     * change-password page finds the old link invalid and forgets the
     * verification made for it.
     */
    public function testAReplacedResetForgetsItsVerificationOnThePage(): void
    {
        $editor = $this->getMember('editor');
        $secret = $this->enroll($editor)['secret'];
        $this->startFreshBrowser();
        $this->assertAsksForCodeFrom($editor, $this->openResetLink($this->requestResetLink($editor)));
        $this->assertSame(200, $this->submitResetCode('totp', fn (): string => $this->getTotpCode($secret))->getStatusCode());
        $this->assertNotNull($this->session()->get(MFAChangePasswordHandler::SESSION_VERIFIED_RESET));

        $this->requestResetLink($editor);
        $page = $this->get(self::CHANGE_PASSWORD_URL);

        $this->assertStringContainsString('invalid or expired', (string) $page->getBody());
        $this->assertNull($this->session()->get(MFAChangePasswordHandler::SESSION_VERIFIED_RESET), 'The verification is forgotten');
        $this->assertNull($this->session()->get(ChangePasswordHandler::MFA_VERIFIED_ON_CHANGE_PASSWORD), 'The module flag is cleared');
    }

    /**
     * Mismatched new-password fields after a successful code. Where they are
     * refused depends on the framework version: from 6.1 the form's
     * ConfirmedPasswordField refuses them in form validation, before
     * doChangePassword() runs; before 6.1 the framework's doChangePassword()
     * refuses them itself, after the module's code check has let the
     * submission through, and the module's clean-up after the action keeps
     * the verification for the live reset. Either way the reloaded form
     * keeps the verification (createChangePasswordResponse() finds it
     * matches the live reset), and the corrected submission completes
     * without another code.
     */
    public function testAMismatchedPasswordRetryNeedsNoSecondCode(): void
    {
        $editor = $this->getMember('editor');
        $secret = $this->enroll($editor)['secret'];
        $this->startFreshBrowser();
        $password = (string) $this->reloadMember($editor)->Password;
        $this->assertAsksForCodeFrom($editor, $this->openResetLink($this->requestResetLink($editor)));
        $this->assertSame(200, $this->submitResetCode('totp', fn (): string => $this->getTotpCode($secret))->getStatusCode());

        $this->assertShowsPasswordForm($this->get(self::CHANGE_PASSWORD_URL));
        $refused = $this->submitForm(
            'ChangePasswordForm_ChangePasswordForm',
            null,
            $this->getChangePasswordFormData(self::NEW_PASSWORD, 'Different-Correct-Horse-2026')
        );

        $this->assertRetryKeepsTheVerification($editor, $password, $refused, $this->getPasswordMismatchMessage());
        $this->assertLandsInTheCMSAs($editor, $this->submitNewPassword());
    }

    /**
     * A new password the configured password validator refuses after a
     * successful code. It passes form validation, so doChangePassword()
     * runs and the framework refuses it there; the clean-up after the action
     * keeps the verification for the live reset, and the retry with an
     * acceptable password completes without another code.
     *
     * SapphireTest switches password validation off in setUp(), so a
     * validator is put back for this test: the framework's
     * EntropyPasswordValidator, the default framework/_config/passwords.yml
     * configures.
     */
    public function testAPasswordTheValidatorRefusesCanBeRetriedWithoutASecondCode(): void
    {
        $editor = $this->getMember('editor');
        $secret = $this->enroll($editor)['secret'];
        $this->startFreshBrowser();
        $password = (string) $this->reloadMember($editor)->Password;
        Member::set_password_validator(EntropyPasswordValidator::create());
        $weak = 'password';
        $this->assertFalse(
            Member::password_validator()->validate($weak, $this->reloadMember($editor))->isValid(),
            'The configured password validator refuses it'
        );
        $this->assertAsksForCodeFrom($editor, $this->openResetLink($this->requestResetLink($editor)));
        $this->assertSame(200, $this->submitResetCode('totp', fn (): string => $this->getTotpCode($secret))->getStatusCode());

        $refused = $this->submitNewPassword($weak);

        $this->assertRetryKeepsTheVerification($editor, $password, $refused, 'The password strength is too low');
        $this->assertLandsInTheCMSAs($editor, $this->submitNewPassword());
    }

    /**
     * The module shows the code prompt instead of the form, but never checked
     * the form's submission: a direct post changed an enrolled member's
     * password, and cleared their lockout, with no code.
     */
    public function testTheNewPasswordCannotBePostedWithoutTheCode(): void
    {
        $editor = $this->getMember('editor');
        $this->enroll($editor);
        $this->startFreshBrowser();
        $password = (string) $this->reloadMember($editor)->Password;

        $this->assertAsksForCodeFrom($editor, $this->openResetLink($this->requestResetLink($editor)));
        $refused = $this->postNewPasswordDirectly();

        $this->assertSame(302, $refused->getStatusCode());
        $this->assertStringContainsString(self::CHANGE_PASSWORD_URL, $this->getLocation($refused));
        $this->assertNothingChanged($editor, $password);
    }

    /**
     * Once a reset with one code logs the member in, the reset prompt is a
     * way into the CMS and is throttled as the login's code step is: each
     * wrong code counts, and a locked account is refused even a right code.
     */
    public function testWrongCodesOnTheResetPromptCountTowardsTheLockout(): void
    {
        $editor = $this->getMember('editor');
        $secret = $this->enroll($editor)['secret'];
        $this->startFreshBrowser();
        $this->assertAsksForCodeFrom($editor, $this->openResetLink($this->requestResetLink($editor)));
        $this->getJSON(self::RESET_MFA_URL . '/login/totp');
        $failedBefore = (int) $this->reloadMember($editor)->FailedLoginCount;
        $wrong = $this->getWrongTotpCode($secret);

        $this->assertSame(401, $this->postJSON(self::RESET_MFA_URL . '/login/totp', ['code' => $wrong])->getStatusCode());
        $this->assertSame($failedBefore + 1, (int) $this->reloadMember($editor)->FailedLoginCount);

        $limit = (int) Member::config()->get('lock_out_after_incorrect_logins');
        for ($i = 1; $i < $limit; $i++)
        {
            $this->assertSame(401, $this->postJSON(self::RESET_MFA_URL . '/login/totp', ['code' => $wrong])->getStatusCode());
        }
        $this->assertTrue($this->reloadMember($editor)->isLockedOut());

        $locked = $this->postJSON(self::RESET_MFA_URL . '/login/totp', ['code' => $this->getTotpCode($secret)]);
        $this->assertSame(403, $locked->getStatusCode());
        $this->assertStringContainsString('temporarily locked', (string) $locked->getBody());
        $this->assertAsksForCodeFrom($editor, $this->get(self::CHANGE_PASSWORD_URL));
        $this->assertNull($this->getLoggedInMemberID());
    }

    /**
     * silverstripe-mfa#516 stays closed: an unenrolled member is never asked
     * for a code, is logged in by the framework without a marker, and the
     * guard sends them to the login, which requires enrolment.
     */
    public function testAnUnenrolledResetStillEndsAtTheLoginAndEnrollment(): void
    {
        $editor = $this->getMember('editor');

        $this->assertShowsPasswordForm($this->openResetLink($this->requestResetLink($editor)));
        $changed = $this->submitNewPassword();

        $this->assertSame(302, $changed->getStatusCode());
        $this->assertSame((int) $editor->ID, $this->getLoggedInMemberID(), 'The framework logged the member in');
        $this->assertNull($this->getSessionMarker(), 'Without the MFA marker');
        $this->assertNull($this->session()->get(MFAChangePasswordHandler::SESSION_VERIFIED_RESET));

        $admin = $this->get('admin/pages');
        $this->assertSame(302, $admin->getStatusCode());
        $this->assertStringContainsString('Security/login', $this->getLocation($admin));
        $this->assertNull($this->getLoggedInMemberID(), 'The guard logged them out');

        $this->assertRedirectsToMFA($this->submitPassword($editor->Email, self::NEW_PASSWORD, '/admin/pages'));
        $schema = $this->getJSON(self::MFA_URL . '/schema');
        $this->assertEmpty($schema['registeredMethods'], 'The next step is registration');
        $this->assertFalse((bool) $schema['canSkip']);
    }

    /**
     * Not a reset: a logged-in member changes their own password with their
     * current one, as before, and keeps their session and its marker.
     */
    public function testALoggedInMemberStillChangesTheirOwnPassword(): void
    {
        $editor = $this->getMember('editor');
        $this->enroll($editor);
        $password = (string) $this->reloadMember($editor)->Password;

        $body = (string) $this->get(self::CHANGE_PASSWORD_URL)->getBody();
        $this->assertStringContainsString($this->getCurrentPasswordFieldName(), $body);
        $this->assertStringNotContainsString('id="mfa-app"', $body);
        $changed = $this->submitForm(
            'ChangePasswordForm_ChangePasswordForm',
            null,
            $this->getChangePasswordFormData(self::NEW_PASSWORD, null, self::PASSWORD)
        );

        $this->assertSame(302, $changed->getStatusCode());
        $this->assertSame((int) $editor->ID, $this->getLoggedInMemberID());
        $this->assertSame((int) $editor->ID, $this->getSessionMarker());
        $this->assertSame(200, $this->get('admin/pages')->getStatusCode());
        $this->assertNotSame($password, (string) $this->reloadMember($editor)->Password, 'The password changed');
    }
}
