<?php

namespace Fromholdio\MFAGuard\Tasks;

use Fromholdio\MFAGuard\Services\MemberSessionRevoker;
use SilverStripe\Dev\BuildTask;
use SilverStripe\MFA\Model\RegisteredMethod;
use SilverStripe\PolyExecution\PolyOutput;
use SilverStripe\Security\Member;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Throwable;

/**
 * The server-side break-glass for CMS MFA: removes one member's registered
 * MFA methods, backup codes included, so they enrol afresh at their next
 * sign-in.
 *
 *     vendor/bin/sake tasks:mfa-reset --email=person@example.com
 *
 * The everyday recoveries are the member's own backup codes and the account
 * reset email an administrator sends from Security. This task is for when
 * neither can work:
 *
 * - Total lockout: every administrator has lost their authenticator and
 *   their backup codes, so nobody can sign in to send a reset.
 * - Lost secret: SS_MFA_SECRET_KEY was lost or changed, so no stored TOTP
 *   secret decrypts and every TOTP sign-in fails.
 *
 * It does what the MFA module's own account reset does to MFA
 * (MFAResetExtension::handleAccountReset()): deletes each RegisteredMethod
 * through the ORM and clears HasSkippedMFARegistration. Then it ends every
 * session the member has open, through MemberSessionRevoker, as a completed
 * account reset does: a session left open on a lost or compromised device
 * would otherwise carry on regardless. Each is logged out at its next
 * request, and the output says how many ended.
 *
 * By default it also replaces the password with a long random one nobody
 * sees, so the member must use "I've lost my password" before they can sign
 * in. Otherwise anyone holding the old password could sign in before the
 * member does and enrol an authenticator of their own, and a lost or stolen
 * phone, the usual reason to run this, is also a likely place for that
 * password to be. The emailed reset proves the member holds the inbox, as the
 * account reset email does by making them choose a new password. The random
 * password is validated before anything changes, so a rejection leaves the
 * member as they were. On a live site the framework emails the member that
 * their password changed. --keep-password leaves the password alone: for a
 * lost SS_MFA_SECRET_KEY, where every member is reset and no password is in
 * doubt, or when email is not working. The lockout state is left alone either
 * way. One member per run, by the exact address, so a typo cannot widen it.
 *
 * The member is found by their Email field. A site that signs members in by
 * another unique_identifier_field, or allows duplicate email addresses, needs
 * its own handling before relying on this task (see docs/recovery.md).
 *
 * Command line only: whoever can run it already holds the server, which is
 * the trust it relies on. It returns Command::FAILURE, with the reason as
 * its last line, when --email is missing or matches no member or the random
 * password is rejected, and Command::SUCCESS otherwise, including for a
 * member with nothing to remove.
 */
class MFAResetTask extends BuildTask
{
    protected static string $commandName = 'mfa-reset';

    protected string $title = 'Reset a member\'s MFA';

    protected static string $description = 'Removes one member\'s registered MFA methods and backup codes, ends '
        . 'their open sessions and, unless --keep-password, replaces their password with a random one, so they reset '
        . 'it by email and set up MFA again. The break-glass for a total lockout or a lost SS_MFA_SECRET_KEY.';

    private static bool $can_run_in_browser = false;


    /**
     * Core
     * ----------------------------------------------------
     */

    public static function getHelp(): string
    {
        return 'Finds the member whose email is exactly --email, deletes their registered MFA methods (authenticator '
            . 'app and backup codes), clears their skipped-registration flag and ends every session they have open, on '
            . 'every device. Unless --keep-password is given, their password is replaced with a random one nobody '
            . 'knows, so they must use "I\'ve lost my password" before signing in. They are asked to set up MFA at '
            . 'their next sign-in. See docs/recovery.md in fromholdio/silverstripe-mfa-guard.';
    }

    public function getOptions(): array
    {
        return [
            new InputOption(
                'email',
                null,
                InputOption::VALUE_REQUIRED,
                'The email address of the member whose MFA methods are removed'
            ),
            new InputOption(
                'keep-password',
                null,
                InputOption::VALUE_NONE,
                'Leave the member\'s password unchanged: for a lost SS_MFA_SECRET_KEY, or when email is not working'
            ),
        ];
    }

    protected function execute(InputInterface $input, PolyOutput $output): int
    {
        $email = $this->readEmail($input);
        if (is_null($email))
        {
            $output->writeln('The --email option is required: the email address of the member to reset.');
            return Command::FAILURE;
        }

        $member = Member::get()->filter('Email', $email)->first();
        if (is_null($member))
        {
            $output->writeln(sprintf('No member has the email address "%s". Nothing was changed.', $email));
            return Command::FAILURE;
        }

        $methods = $member->RegisteredMFAMethods();
        $count = $methods->count();
        $output->writeln(sprintf('Member: %s (ID %d).', $member->Email, $member->ID));

        // Validated before anything changes; written with the flag below.
        $doReplacePassword = !$input->getOption('keep-password');
        if ($doReplacePassword)
        {
            $result = $member->changePassword($this->generateRandomPassword(), false);
            if (!$result->isValid())
            {
                $output->writeln(sprintf(
                    'The random password was rejected: %s Nothing was changed.',
                    implode(' ', array_column($result->getMessages(), 'message'))
                ));
                return Command::FAILURE;
            }
        }

        foreach ($methods as $method)
        {
            $output->writeln(sprintf('Removing %s (registered %s).', $this->getMethodLabel($method), $method->Created));
            $method->delete();
        }

        $member->HasSkippedMFARegistration = false;
        $member->write();

        if ($count === 0)
        {
            $output->writeln('The member had no registered MFA methods; nothing was removed.');
        }
        else
        {
            $output->writeln(sprintf('Removed %d registered MFA method(s).', $count));
        }

        if ($doReplacePassword)
        {
            $output->writeln('Replaced their password with a random one nobody knows. They must use "I\'ve lost my '
                . 'password" on the login page to choose a new one.');
        }
        else
        {
            $output->writeln('Their password is unchanged (--keep-password).');
        }

        $revoked = MemberSessionRevoker::singleton()->revokeAllSessions($member);
        $output->writeln(sprintf(
            'Ended %d login session(s); each is logged out at its next request.',
            $revoked['loginSessions']
        ));
        if ($revoked['rememberLoginHashes'] > 0)
        {
            $output->writeln(sprintf(
                'Removed %d "keep me signed in" token(s).',
                $revoked['rememberLoginHashes']
            ));
        }

        $output->writeln('They will be asked to set up MFA at their next sign-in.');
        return Command::SUCCESS;
    }


    /**
     * Getters
     * ----------------------------------------------------
     */

    protected function readEmail(InputInterface $input): ?string
    {
        $value = $input->getOption('email');
        if (!is_string($value) || trim($value) === '')
        {
            return null;
        }
        return trim($value);
    }

    /**
     * A password nobody will type: 64 hexadecimal characters from 32 random
     * bytes, well beyond any strength rule.
     */
    protected function generateRandomPassword(): string
    {
        return bin2hex(random_bytes(32));
    }

    /**
     * The method's display name, or its stored class name when the method can
     * no longer be built (its module removed), so a break-glass run never
     * fails on the label.
     */
    protected function getMethodLabel(RegisteredMethod $method): string
    {
        try
        {
            return $method->getMethod()->getName();
        }
        catch (Throwable $exception)
        {
            return (string) $method->MethodClassName;
        }
    }
}
