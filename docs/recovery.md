# Recovery

Work through these in order; the first that applies is the one to use.

## 1. Lost phone, recovery codes available

Sign in with a recovery code: choose **More options** on the code screen, then **Verify with recovery codes**. Each code works once. Then open your profile in the CMS, choose **Verify to continue**, and use **Reset** on the authenticator app to enrol the new phone. Reset the recovery codes too if several have been used.

## 2. Lost phone and recovery codes: account reset

An administrator with the MFA module's "Administer other users' MFA methods" permission (included in `ADMIN`) opens the member in Security, chooses **Verify to continue**, then **Send account reset email**.

1. The member follows the emailed link, which is valid for 48 hours.
2. They set a new password. Their MFA methods are removed.
3. They sign in with the new password and enrol again.

Completing the reset ends every session the member had open, on every device; each is logged out at its next request. Sending the email ends nothing: until the member completes the reset their credentials are unchanged. The reset page opens only in a logged-out browser. The account reset needs working email and also clears any lockout.

## 3. Forgotten password

"I've lost my password" on the login page works as usual.

- **An enrolled member** enters one code from their authenticator app, or a recovery code, before the new-password form. After setting the new password they are signed in with MFA done.
- **A member who has not enrolled** sets a new password and is then logged out by the guard; their next sign-in requires enrolment.
- **A member who registered an app but did not save their recovery codes** enters a code and sets the new password, but is not signed in; at their next sign-in they finish enrolling first.

How the single code stays safe:

- **It counts for one member and one reset.** The code is recorded against the member who entered it and a digest of the reset link they opened. A code entered for another account, or during an earlier reset that was never finished, does not unlock the form.
- **The new password needs it.** For an enrolled member the new password is refused unless the code was entered for that reset, even when the form is posted directly.
- **Wrong codes count towards the lockout**, as at sign-in, and a locked account is refused a code on the reset too.

## 4. Locked out after wrong attempts

Wrong passwords and wrong codes share `Member.lock_out_after_incorrect_logins` and `Member.lock_out_delay_mins`. Wait for the lockout to expire, or have an administrator send an account reset, which clears it.

## Break-glass: `tasks:mfa-reset`

For when nobody can sign in to send an account reset, or when every authenticator-app sign-in fails because `SS_MFA_SECRET_KEY` was lost. Run it on the server, as the web server user, from the project root:

```bash
vendor/bin/sake tasks:mfa-reset --email=person@example.com
```

- **What it does.** Deletes that member's registered MFA methods, recovery codes included, and clears their skipped-registration flag, as the account reset does. Then it ends every session the member has open and removes any remember-login tokens, and reports how many it ended.
- **The password.** By default it replaces the password with a random one nobody knows, so anyone holding the old password cannot sign in and enrol their own authenticator first. The member uses "I've lost my password", which proves they hold the inbox. The random password is validated first; if the site's password validator rejects it, nothing changes and the task fails.
- **`--keep-password`** leaves the password alone: for a lost encryption key, where every member is reset and no password is in doubt, or when email is not working. It leaves the risk that someone holding the password enrols first.
- **The lockout** is left as it is.
- **Exit status.** Fails, changing nothing, when `--email` is missing or matches no member, or when the random password is rejected. Succeeds otherwise, including when the member had nothing to remove.
- **Command line only.** Whoever can run it already controls the server.

The member is found by the exact value of their `Email` field. A site that signs members in by another `Member.unique_identifier_field`, or that allows duplicate email addresses, needs its own handling before relying on the task.

## Lost `SS_MFA_SECRET_KEY`

1. Restore the key from the environment's secrets backup if at all possible. Nothing else is needed then.
2. Otherwise generate a new key, set it, and run `tasks:mfa-reset --keep-password` for every member with CMS access. Each enrols again at their next sign-in.

## Ending sessions

A member's own CMS profile lists their login sessions (`silverstripe/session-manager`), where another session can be logged out. Resetting the authenticator app or recovery codes from the profile does not end other sessions. A completed account reset and the break-glass task end all of them.

Ending sessions deletes the session-manager records, and each session is logged out at its next request. A sign-in completing at the same moment as the reset can escape it: the records are read and deleted without a lock. Both resets remove the MFA methods first, which narrows that window without closing it. The break-glass task performs several writes in sequence and is not a single transaction.
