# Compatibility and limits

## Supported and tested versions

| Component | Constraint | Minimum, source-reviewed | Tested |
| --- | --- | --- | --- |
| PHP | `^8.3` | 8.3 | 8.5.8 |
| `silverstripe/framework` | `^6.0.4` | 6.0.4 | 6.2.11 |
| `silverstripe/mfa` | `^6.0` | 6.0.0 | 6.2.2 |
| `silverstripe/totp-authenticator` | `^6.0` | 6.0.0 | 6.1.1 |
| `silverstripe/session-manager` | `^3.0` | 3.0.0 | 3.1.4 |
| `silverstripe/siteconfig` | `^6.0` | 6.0.0 | 6.1.1 |
| `silverstripe/cms` (test suite only) | `^6.0` (dev) | 6.0.0 | 6.2.5 |
| `phpunit/phpunit` (test suite only) | `^11.5` (dev) | 11.5.0 | 11.5.57 |

- **Tested.** The module's full test suite has been run on PHP 8.5 with Silverstripe CMS 6.2, using the versions in the Tested column.
- **Minimums.** The lower bounds come from reading the tagged source of each minimum release against the classes, hooks and configuration this module uses. No incompatibility was found, but nothing below the tested versions has been run, including PHP 8.3 and 8.4 and Silverstripe CMS 6.0 and 6.1. Run the module's suite on your project before relying on an untested combination; see [testing.md](testing.md).
- **Framework 6.0.4.** Framework 6.0.0 to 6.0.3 show the new-password form for a forgotten-password reset link that has since been replaced, where 6.0.4 and later report the link as invalid, as the module's tests expect. This minimum is also set from the tagged source change, not from a test run.
- **PHP and Silverstripe CMS minors.** Upstream supports PHP 8.3 and 8.4 on Silverstripe CMS 6.0 and 6.1; PHP 8.5 support starts with Silverstripe CMS 6.2. The `^8.3` constraint does not extend an older CMS release's PHP support, so follow the upstream [server requirements](https://docs.silverstripe.org/en/6/getting_started/server_requirements/).

## Upstream drift checks

Three classes depend on details of the upstream modules beyond their public extension points. The test suite fails when those details change.

- **`TOTPRegisterHandler::start()`** is derived from `RegisterHandler::start()` in `silverstripe/totp-authenticator` 6.1.1, which is unchanged from 6.0.0. `TOTPRegisterHandlerTest` fingerprints the installed method and fails when it changes. Re-read the upstream method, bring the copy into line, then update the fingerprint; never update the fingerprint alone.
- **`MFAChangePasswordHandler`** wraps the MFA module's `verifyMFACheck()` and `createChangePasswordResponse()` and the framework's `doChangePassword()`. It relies on `verifyMFACheck()` answering 200 for a complete code and 401 for a wrong one, on the MFA module's `MFA_VERIFIED_ON_CHANGE_PASSWORD` session flag, on the framework's `AutoLoginHash` session key and on `EnforcementManager::hasCompletedRegistration()`. `MFAChangePasswordHandlerTest` exercises each through the real endpoints.
- **`MFALoginHandler`** overrides the MFA module's `doLogin()`, `checkLogin()` and `doPerformLogin()`. `MFALoginFlowTest` covers each route through them.

A project that depends on this module does not run its tests automatically. Run the module's suite on the project after any update to these modules; see [testing.md](testing.md).

## What the module does not cover

- **Only requests through the Silverstripe middleware chain.** The guard protects requests that pass through the Director's middleware with the framework's authentication. It is not MFA for a separate application on the same domain, for an API token scheme, or for an authenticator that establishes a member later in a request than `AuthenticationMiddleware`.
- **Only mandatory MFA for CMS members.** Optional MFA and grace periods need their own guard semantics and are not supported; see [configuration.md](configuration.md#the-supported-profile). The session marker records which member passed MFA, not under which policy, so a policy change should be followed by ending existing sessions.
- **The authenticator app and recovery codes.** Other MFA methods can be registered with the MFA module, but only these two have been tested with this module.
- **Session ending is not instantaneous or transactional.** See [recovery.md](recovery.md#ending-sessions).
- **The break-glass task finds members by email.** See [recovery.md](recovery.md#break-glass-tasksmfa-reset).
- **"Keep me signed in" is off site-wide**, including for front-end members.
