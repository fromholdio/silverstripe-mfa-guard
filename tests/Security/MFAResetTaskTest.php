<?php

namespace Fromholdio\MFAGuard\Tests\Security;

use Fromholdio\MFAGuard\Tasks\MFAResetTask;
use Fromholdio\MFAGuard\Tests\Support\LoginSessionAssertions;
use Fromholdio\MFAGuard\Tests\Support\MFAFunctionalTestCase;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\Core\Validation\ValidationResult;
use SilverStripe\MFA\Model\RegisteredMethod;
use SilverStripe\ORM\FieldType\DBDatetime;
use SilverStripe\PolyExecution\PolyOutput;
use SilverStripe\Security\Member;
use SilverStripe\Security\RememberLoginHash;
use SilverStripe\Security\Validation\PasswordValidator;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\ArrayInput;
use Symfony\Component\Console\Input\InputDefinition;
use Symfony\Component\Console\Output\BufferedOutput;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * The break-glass task removes one member's MFA methods and nobody else's,
 * ends that member's sessions and nobody else's,
 * replaces their password with a random one unless --keep-password is given,
 * fails cleanly for a missing or unknown address or a rejected password, and
 * leaves the member to enrol again at their next sign-in. The forgotten-
 * password reset that follows the replaced password is covered by
 * MFAChangePasswordHandlerTest.
 */
class MFAResetTaskTest extends MFAFunctionalTestCase
{
    use LoginSessionAssertions;

    protected static $fixture_file = 'MFATest.yml';

    protected function runTask(array $parameters): array
    {
        $task = MFAResetTask::create();
        $input = new ArrayInput($parameters, new InputDefinition($task->getOptions()));
        $buffer = new BufferedOutput();
        $output = new PolyOutput(PolyOutput::FORMAT_ANSI, OutputInterface::VERBOSITY_NORMAL, false, $buffer);
        $exitCode = $task->run($input, $output);
        return [$exitCode, $buffer->fetch()];
    }

    protected function getMethodCount(Member $member): int
    {
        return RegisteredMethod::get()->filter('MemberID', $member->ID)->count();
    }

    /**
     * A "keep me signed in" token for the member, written through the ORM.
     * The login never issues one, because autologin is off; this stands in
     * for one left from before that was so.
     */
    protected function createRememberLoginHash(Member $member): RememberLoginHash
    {
        $hash = RememberLoginHash::create();
        $hash->MemberID = (int) $member->ID;
        $hash->DeviceID = bin2hex(random_bytes(20));
        $hash->Hash = bin2hex(random_bytes(32));
        $hash->ExpiryDate = date('Y-m-d H:i:s', DBDatetime::now()->getTimestamp() + 14 * 86400);
        $hash->write();
        return $hash;
    }

    protected function getRememberLoginHashCount(Member $member): int
    {
        return RememberLoginHash::get()->filter('MemberID', $member->ID)->count();
    }


    /**
     * Tests
     * ----------------------------------------------------
     */

    public function testTheCommandName(): void
    {
        $this->assertSame('tasks:mfa-reset', MFAResetTask::getName());
        $this->assertFalse((bool) MFAResetTask::config()->get('can_run_in_browser'));
    }

    public function testItRemovesOneMembersMethodsAndNobodyElses(): void
    {
        $editor = $this->objFromFixture(Member::class, 'editor');
        $other = $this->objFromFixture(Member::class, 'othereditor');
        $this->enroll($editor);
        $this->startFreshBrowser();
        $this->enroll($other);
        $this->startFreshBrowser();

        [$exitCode, $text] = $this->runTask(['--email' => $editor->Email]);

        $this->assertSame(Command::SUCCESS, $exitCode, $text);
        $this->assertSame(0, $this->getMethodCount($editor));
        $this->assertSame(2, $this->getMethodCount($other));
        $this->assertStringContainsString('Removed 2 registered MFA method(s).', $text);
        $this->assertStringContainsString('next sign-in', $text);
    }

    public function testItReplacesThePasswordByDefault(): void
    {
        $editor = $this->objFromFixture(Member::class, 'editor');
        $other = $this->objFromFixture(Member::class, 'othereditor');
        $this->enroll($editor);
        $this->startFreshBrowser();

        [$exitCode, $text] = $this->runTask(['--email' => $editor->Email]);

        $this->assertSame(Command::SUCCESS, $exitCode, $text);
        $this->assertStringContainsString('Replaced their password with a random one nobody knows.', $text);
        $this->assertEmailSent($editor->Email, null, 'Your password has been changed');

        $this->assertStringEndsNotWith(
            self::MFA_URL,
            $this->getLocation($this->submitPassword($editor->Email)),
            'The old password no longer signs in'
        );
        $this->startFreshBrowser();
        $this->assertRedirectsToMFA($this->submitPassword($other->Email));
    }

    public function testKeepPasswordLeavesItAndLeadsToEnrollment(): void
    {
        $editor = $this->objFromFixture(Member::class, 'editor');
        $this->enroll($editor);
        $this->startFreshBrowser();

        [$exitCode, $text] = $this->runTask(['--email' => $editor->Email, '--keep-password' => true]);

        $this->assertSame(Command::SUCCESS, $exitCode, $text);
        $this->assertStringContainsString('Their password is unchanged (--keep-password).', $text);
        $this->assertNull($this->findEmail($editor->Email, null, 'Your password has been changed'));

        $this->assertRedirectsToMFA($this->submitPassword($editor->Email));
        $schema = $this->getJSON(self::MFA_URL . '/schema');
        $this->assertEmpty($schema['registeredMethods'], 'The member is prompted to enrol');
    }

    public function testARejectedPasswordChangesNothing(): void
    {
        $editor = $this->objFromFixture(Member::class, 'editor');
        [, $laptop] = $this->enrollOnNewBrowser($editor);
        $this->startFreshBrowser();
        Injector::inst()->registerService(
            new class extends PasswordValidator
            {
                public function validate(string $password, Member $member): ValidationResult
                {
                    $result = ValidationResult::create();
                    $result->addError('Rejected for the test.');
                    return $result;
                }
            },
            PasswordValidator::class
        );

        [$exitCode, $text] = $this->runTask(['--email' => $editor->Email]);

        $this->assertSame(Command::FAILURE, $exitCode, $text);
        $this->assertStringContainsString('The random password was rejected: Rejected for the test. Nothing was changed.', $text);
        $this->assertStringNotContainsString('Removing', $text);
        $this->assertSame(2, $this->getMethodCount($editor));
        $this->assertSame(1, $this->getLoginSessionCount($editor));
        $this->assertBrowserSignedIn($laptop, $editor, 'The member is still signed in after the rejected run');

        $this->startFreshBrowser();
        $this->assertRedirectsToMFA($this->submitPassword($editor->Email));
    }

    public function testAMemberWithNothingToRemoveSucceeds(): void
    {
        [$exitCode, $text] = $this->runTask(['--email' => 'casey.editor@example.com']);

        $this->assertSame(Command::SUCCESS, $exitCode);
        $this->assertStringContainsString('nothing was removed', $text);
    }

    public function testAnUnknownEmailFailsAndChangesNothing(): void
    {
        $editor = $this->objFromFixture(Member::class, 'editor');
        $this->enroll($editor);

        [$exitCode, $text] = $this->runTask(['--email' => 'nobody@example.com']);

        $this->assertSame(Command::FAILURE, $exitCode);
        $this->assertStringContainsString('No member has the email address "nobody@example.com"', $text);
        $this->assertSame(2, $this->getMethodCount($editor));
    }

    public function testAMissingEmailFails(): void
    {
        foreach ([[], ['--email' => '   ']] as $parameters)
        {
            [$exitCode, $text] = $this->runTask($parameters);

            $this->assertSame(Command::FAILURE, $exitCode);
            $this->assertStringContainsString('The --email option is required', $text);
        }
    }

    public function testItEndsOneMembersSessionsAndNobodyElses(): void
    {
        $editor = $this->objFromFixture(Member::class, 'editor');
        [$secret, $laptop] = $this->enrollOnNewBrowser($editor);
        $phone = $this->signInOnNewBrowser($editor, $secret);
        $this->createRememberLoginHash($editor);

        $other = $this->objFromFixture(Member::class, 'othereditor');
        [, $otherBrowser] = $this->enrollOnNewBrowser($other);
        $this->createRememberLoginHash($other);
        $this->startFreshBrowser();

        [$exitCode, $text] = $this->runTask(['--email' => $editor->Email]);

        $this->assertSame(Command::SUCCESS, $exitCode, $text);
        $this->assertStringContainsString('Removed 2 registered MFA method(s).', $text);
        $this->assertStringContainsString('Ended 2 login session(s)', $text);
        $this->assertStringContainsString('Removed 1 "keep me signed in" token(s).', $text);
        $this->assertSame(0, $this->getMethodCount($editor));
        $this->assertSame(0, $this->getLoginSessionCount($editor));
        $this->assertSame(0, $this->getRememberLoginHashCount($editor));

        $this->assertSame(2, $this->getMethodCount($other));
        $this->assertSame(1, $this->getLoginSessionCount($other));
        $this->assertSame(1, $this->getRememberLoginHashCount($other));

        $this->assertBrowserLoggedOut($laptop, 'admin/pages', 'The laptop is logged out on its next request');
        $this->assertBrowserLoggedOut($phone, 'Security/login', 'The phone is logged out on its next request');
        $this->assertBrowserSignedIn($otherBrowser, $other, 'The other member is still signed in');
    }

    public function testAMemberWithNoSessionsReportsNoneEnded(): void
    {
        [$exitCode, $text] = $this->runTask(['--email' => 'casey.editor@example.com']);

        $this->assertSame(Command::SUCCESS, $exitCode);
        $this->assertStringContainsString('Ended 0 login session(s)', $text);
        $this->assertStringNotContainsString('keep me signed in', $text);
    }

    public function testAFailedRunEndsNoSession(): void
    {
        $editor = $this->objFromFixture(Member::class, 'editor');
        [, $laptop] = $this->enrollOnNewBrowser($editor);
        $this->createRememberLoginHash($editor);
        $this->startFreshBrowser();

        foreach ([[], ['--email' => '   '], ['--email' => 'nobody@example.com']] as $parameters)
        {
            [$exitCode, $text] = $this->runTask($parameters);

            $this->assertSame(Command::FAILURE, $exitCode, $text);
            $this->assertStringNotContainsString('Ended', $text);
        }

        $this->assertSame(2, $this->getMethodCount($editor));
        $this->assertSame(1, $this->getLoginSessionCount($editor));
        $this->assertSame(1, $this->getRememberLoginHashCount($editor));
        $this->assertBrowserSignedIn($laptop, $editor, 'The member is still signed in after the failed runs');
    }
}
