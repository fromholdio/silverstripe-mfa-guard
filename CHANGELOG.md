# Changelog

All notable changes to this module are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## 1.0.0 - 2026-10-11

The first stable, public release of the functionality in 0.1.0. There are no source, configuration, test, documentation or dependency changes; this changelog entry is the only difference.

### Compatibility

- Unchanged from 0.1.0: requires PHP 8.3 or later and Silverstripe CMS 6, with `silverstripe/framework` 6.0.4 or later.
- Tested on PHP 8.5 with Silverstripe CMS 6.2, using the code released as 0.1.0. The lower minimums, including PHP 8.3 and 8.4 and Silverstripe CMS 6.0 and 6.1, come from a review of the upstream source and have not been run; see [docs/compatibility.md](docs/compatibility.md).

## 0.1.0 - 2026-10-11

The first release.

### Added

- Mandatory MFA for every member with CMS access, set by configuration, with no grace period and no option to skip. The SiteConfig MFA settings under Settings > Access are hidden.
- A session guard on every request, which logs out any member MFA applies to whose session has not passed MFA as that member. It closes the password-only ways in: a forgotten-password reset of an unenrolled member, the CMS re-login popup, a "keep me signed in" cookie and sessions that predate MFA.
- A login handler that checks the password once per submission, so lockouts happen after the configured number of attempts ([silverstripe-mfa#421](https://github.com/silverstripe/silverstripe-mfa/issues/421)).
- A one-step forgotten-password reset for enrolled members. One code is bound to the member and to the reset link it was entered for, the new password cannot be posted without it, and wrong codes count towards the lockout.
- Ending every session a member has open, on every device, when they complete an administrator-sent account reset.
- `FIO_MFA_ISSUER_NAME`, the name authenticator apps show for the site, applied before the site title can reach the TOTP library.
- The `tasks:mfa-reset` break-glass task, which removes one member's MFA methods, ends their sessions and, by default, replaces their password.

### Compatibility

- Requires PHP 8.3 or later and Silverstripe CMS 6, with `silverstripe/framework` 6.0.4 or later.
- Tested on PHP 8.5 with Silverstripe CMS 6.2. The lower minimums come from a review of the upstream source and have not been run; see [docs/compatibility.md](docs/compatibility.md).

### Side effects

- "Keep me signed in" is turned off for the whole site, including for front-end members.
- The CMS re-login popup is turned off.
- The MFA module's enforcement manager, login handler and change-password handler, and the TOTP module's register handler, are replaced in the Injector. See [docs/configuration.md](docs/configuration.md#injector-replacements).
