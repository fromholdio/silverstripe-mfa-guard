<?php

namespace Fromholdio\MFAGuard\Tests\Support;

use Composer\InstalledVersions;

/**
 * The password fields of the two forms a reset ends in, as the installed
 * framework and MFA module name them. Both forms changed in 6.1, from
 * separate password fields to one ConfirmedPasswordField named Password:
 *
 * - The framework's change-password form: NewPassword1, NewPassword2 and,
 *   for a logged-in member, OldPassword before 6.1; Password[_Password],
 *   Password[_ConfirmPassword] and Password[_CurrentPassword] from 6.1.
 * - The MFA module's account-reset form: NewPassword1 and NewPassword2
 *   before 6.1; Password[_Password] and Password[_ConfirmPassword] from 6.1.
 *
 * The two packages are checked separately, because framework 6.1 can be
 * installed with MFA 6.0. The layout is read from the installed versions
 * rather than from a rendered form, because the direct-post tests submit
 * without ever loading the form. The module's handlers pass the form data
 * through unchanged, so only the tests need to know the layout.
 */
trait PasswordFormFields
{
    /**
     * The first release with the ConfirmedPasswordField layout, as a
     * normalised Composer version, so that 6.1 pre-releases and development
     * branches count as 6.1.
     */
    protected const CONFIRMED_PASSWORD_FIELD_VERSION = '6.1.0.0-dev';

    protected function hasConfirmedFrameworkPasswordField(): bool
    {
        return $this->isInstalledAtLeast('silverstripe/framework', self::CONFIRMED_PASSWORD_FIELD_VERSION);
    }

    protected function hasConfirmedMFAPasswordField(): bool
    {
        return $this->isInstalledAtLeast('silverstripe/mfa', self::CONFIRMED_PASSWORD_FIELD_VERSION);
    }

    protected function isInstalledAtLeast(string $package, string $version): bool
    {
        $installed = InstalledVersions::getVersion($package);
        if (is_null($installed))
        {
            $this->fail($package . ' has no installed version to choose its password fields by');
        }
        return version_compare($installed, $version, '>=');
    }


    /**
     * Framework change-password form
     * ----------------------------------------------------
     */

    /**
     * The new-password field's name, by which the tests tell whether the
     * form is on the page.
     */
    protected function getNewPasswordFieldName(): string
    {
        return $this->hasConfirmedFrameworkPasswordField() ? 'Password[_Password]' : 'NewPassword1';
    }

    /**
     * The current-password field's name, on the form a logged-in member sees.
     */
    protected function getCurrentPasswordFieldName(): string
    {
        return $this->hasConfirmedFrameworkPasswordField() ? 'Password[_CurrentPassword]' : 'OldPassword';
    }

    /**
     * Field values for submitForm() on the change-password form. The
     * confirmation defaults to the password; the current password is for a
     * logged-in member's form only.
     */
    protected function getChangePasswordFormData(string $password, ?string $confirmation = null, ?string $currentPassword = null): array
    {
        $confirmation = $confirmation ?? $password;
        if ($this->hasConfirmedFrameworkPasswordField())
        {
            $data = [
                'Password[_Password]' => $password,
                'Password[_ConfirmPassword]' => $confirmation,
            ];
            if (!is_null($currentPassword))
            {
                $data = ['Password[_CurrentPassword]' => $currentPassword] + $data;
            }
            return $data;
        }

        $data = [
            'NewPassword1' => $password,
            'NewPassword2' => $confirmation,
        ];
        if (!is_null($currentPassword))
        {
            $data = ['OldPassword' => $currentPassword] + $data;
        }
        return $data;
    }

    /**
     * The new password as a raw POST body for the change-password form's
     * action: nested under Password from 6.1, flat before it.
     */
    protected function getChangePasswordPostData(string $password): array
    {
        if ($this->hasConfirmedFrameworkPasswordField())
        {
            return [
                'Password' => [
                    '_Password' => $password,
                    '_ConfirmPassword' => $password,
                ],
            ];
        }
        return [
            'NewPassword1' => $password,
            'NewPassword2' => $password,
        ];
    }

    /**
     * The message the reloaded change-password form shows after mismatched
     * new passwords. From 6.1 the ConfirmedPasswordField refuses them in
     * form validation, before the form's action runs; before 6.1 the
     * framework's doChangePassword() refuses them in the action itself.
     */
    protected function getPasswordMismatchMessage(): string
    {
        return $this->hasConfirmedFrameworkPasswordField()
            ? "Passwords don't match"
            : 'You have entered your new password differently, try again';
    }


    /**
     * MFA account-reset form
     * ----------------------------------------------------
     */

    /**
     * Field values for submitForm() on the MFA module's account-reset form.
     */
    protected function getResetAccountFormData(string $password): array
    {
        if ($this->hasConfirmedMFAPasswordField())
        {
            return [
                'Password[_Password]' => $password,
                'Password[_ConfirmPassword]' => $password,
            ];
        }
        return [
            'NewPassword1' => $password,
            'NewPassword2' => $password,
        ];
    }
}
