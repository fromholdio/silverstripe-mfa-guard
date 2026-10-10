# Silverstripe MFA Guard

Mandatory multi-factor authentication for every Silverstripe CMS member, enforced on every request, with a forgotten-password reset that cannot be used to skip the second factor and recovery tooling for when members are locked out.

It builds on the official [`silverstripe/mfa`](https://github.com/silverstripe/silverstripe-mfa) and [`silverstripe/totp-authenticator`](https://github.com/silverstripe/silverstripe-totp-authenticator) modules. Their sign-in screens, authenticator-app method and recovery codes are used unchanged; this module closes the ways a session can become logged in without passing them.

## What it does

- **Requires MFA by configuration.** Every member with CMS access must enrol and sign in with a second factor. There is no grace period, no "set up later" and no SiteConfig switch an administrator could untick; the now-meaningless MFA settings under Settings > Access are hidden.
- **Guards every request.** A session middleware logs out any member MFA applies to whose session has not passed MFA as that member. On `admin` and `dev` URLs they are sent to the login; elsewhere the request carries on as an anonymous visitor's, so they get no draft pages, archived versions or protected files. This closes the password-only ways in: a forgotten-password reset of an unenrolled member, the CMS re-login popup, a "keep me signed in" cookie and sessions that predate MFA.
- **Counts a wrong password once.** The login handler checks the password once per submission instead of twice ([silverstripe-mfa#421](https://github.com/silverstripe/silverstripe-mfa/issues/421)), so lockouts happen after the configured number of attempts.
- **Makes a forgotten-password reset safe and one-step.** An enrolled member enters one code during the reset and ends signed in with MFA done. That code is bound to the member and to the reset link it was entered for, the new password cannot be posted without it, wrong codes count towards the lockout, and a member who has not finished enrolling must still finish.
- **Ends sessions on account reset.** Completing an administrator-sent account reset ends every session the member had open, on every device.
- **Names the site in authenticator apps.** The issuer shown in authenticator apps comes from `FIO_MFA_ISSUER_NAME`, chosen before the site title can reach the TOTP library, so a title containing a colon cannot break enrolment.
- **Provides a break-glass task.** `tasks:mfa-reset` removes one member's MFA methods, ends their sessions and, by default, replaces their password so only the inbox owner can get back in.

## Requirements

- PHP 8.3 or later, within the PHP versions your Silverstripe CMS release supports
- Silverstripe CMS 6, with `silverstripe/framework` 6.0.4 or later, `silverstripe/mfa` 6, `silverstripe/totp-authenticator` 6, `silverstripe/session-manager` 3 and `silverstripe/siteconfig` 6

The module has been tested on PHP 8.5 with Silverstripe CMS 6.2. The lower minimums come from a review of the upstream source and have not been run; see [docs/compatibility.md](docs/compatibility.md).

## Installation

```bash
composer require fromholdio/silverstripe-mfa-guard
vendor/bin/sake db:build --flush
```

Then set the environment variables below. Read [Side effects](#side-effects) before installing on a site with front-end member logins.

## Environment variables

| Variable | Required | Purpose |
| --- | --- | --- |
| `SS_MFA_SECRET_KEY` | Yes | The MFA module's encryption key for stored authenticator secrets. Generate once per environment, for example with `openssl rand -hex 32`, keep it with that environment's secrets and never rotate it casually. |
| `FIO_MFA_ISSUER_NAME` | Recommended | The name authenticator apps show for the site. Must not contain a colon. Unset or empty keeps the TOTP module's default, the SiteConfig title. Set it before anyone enrols, because it is written into the QR code. |
| `BYPASS_MFA` | Local development only | The MFA module's switch: present with any value, it turns MFA and this module's guard off. Never set it on a shared or production environment. |

```dotenv
SS_MFA_SECRET_KEY="<64 hexadecimal characters>"
FIO_MFA_ISSUER_NAME="Example CMS"
```

## Side effects

- **"Keep me signed in" is turned off for the whole site** (`Security.autologin_enabled: false`), because a remember-login cookie starts a session without the second factor ([silverstripe-mfa#384](https://github.com/silverstripe/silverstripe-mfa/issues/384)). This also affects members who sign in to the front end.
- **The CMS re-login popup is turned off** (`CMSSecurity.reauth_enabled: false`). An expired CMS session goes back through the full login.
- **Four services are replaced in the Injector:** the MFA module's enforcement manager, login handler and change-password handler, and the TOTP module's register handler. Another module that replaces any of them cannot be combined with this one without integration work; see [docs/configuration.md](docs/configuration.md#injector-replacements).

## Recovery

Members recover with their recovery codes, or an administrator sends an account reset email from Security. When nobody can sign in, run the break-glass task on the server:

```bash
vendor/bin/sake tasks:mfa-reset --email=person@example.com
vendor/bin/sake tasks:mfa-reset --email=person@example.com --keep-password
```

See [docs/recovery.md](docs/recovery.md) for every recovery path, including a lost `SS_MFA_SECRET_KEY`.

## Running the tests

The module's suite runs from the root of a Silverstripe CMS project that has the module installed:

```bash
vendor/bin/phpunit -c vendor/fromholdio/silverstripe-mfa-guard/phpunit.xml.dist
```

Composer does not load a dependency's `autoload-dev`, so the module's `tests/bootstrap.php` registers its test namespace itself. The database user needs permission to create the temporary `ss_tmpdb_*` databases. See [docs/testing.md](docs/testing.md), which also explains how a project's own functional tests can reach the CMS with the guard in place.

## Documentation

- [Configuration](docs/configuration.md): settings, Injector replacements, middleware and config ordering.
- [Recovery](docs/recovery.md): recovery codes, account reset, forgotten password, the break-glass task and a lost encryption key.
- [Compatibility and limits](docs/compatibility.md): supported and tested versions, upstream drift checks and what the module does not cover.
- [Testing](docs/testing.md): running the suite and writing host tests.
- [Changelog](CHANGELOG.md): changes in each release.

## Licence

BSD 3-Clause; see [LICENSE](LICENSE). Parts of two classes are adapted from third-party code under the MIT and BSD 3-Clause licences; see [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).
