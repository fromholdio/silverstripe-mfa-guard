# Testing

## Running the module's suite

Run it from the root of a Silverstripe CMS 6 project that has the module installed. The suite has been run on Silverstripe CMS 6.2 with PHP 8.5; see [compatibility.md](compatibility.md) for the versions it has not been run on.

```bash
vendor/bin/phpunit -c vendor/fromholdio/silverstripe-mfa-guard/phpunit.xml.dist
```

To run it from another directory, set `MFA_GUARD_PROJECT_ROOT` to the project root.

- **Why the separate configuration.** Composer loads `autoload-dev` only for the root package, so a project cannot autoload `Fromholdio\MFAGuard\Tests\` by itself, and PHPUnit loads the test classes before Silverstripe's class manifest is available. `tests/bootstrap.php` registers that namespace with the project's Composer autoloader and then runs the framework's own test bootstrap.
- **Database permissions.** Like any Silverstripe suite, the tests create temporary `ss_tmpdb_*` databases, so the configured database user needs permission to create and drop databases. Where the site's user cannot, run the suite with a privileged user's credentials in `SS_DATABASE_USERNAME` and `SS_DATABASE_PASSWORD`; variables already in the environment take precedence over `.env`.
- **New test classes.** After adding or renaming test classes, run once with `SS_PHPUNIT_FLUSH=1` so the test manifest finds them.
- **The CMS is required.** The guard tests use a versioned page, the CMS routes under `admin/pages` and the MFA module's administrator endpoints.
- **No authenticator app is needed.** The registration endpoint returns the secret, and the tests compute the current code with `OTPHP\TOTP`, waiting for a fresh 30-second window when few seconds remain. No email leaves the test run; the framework's test mailer captures it.
- **`BYPASS_MFA`.** The tests switch MFA enforcement back on in setup, so the suite runs the same with or without `BYPASS_MFA` in the environment. Tests that need it off switch it off themselves.
- **Password form fields.** The framework's change-password form and the MFA module's account-reset form renamed their password fields in 6.1, when both moved to a single `ConfirmedPasswordField`. `Tests\Support\PasswordFormFields` chooses the field names from the installed version of each package, checked separately, so the same tests submit either layout. Only the 6.1 and later layout has been exercised so far.

## Test fixtures in a project's manifest

Silverstripe's test kernel scans the `tests` directory of every installed module, so the module's `TestOnly` classes are in a project's test manifest when the project runs its own suite. They are namespaced under `Fromholdio\MFAGuard\Tests\`, and the one fixture with a table, `MFAGuardProbePage`, uses the table `MFAGuardTest_ProbePage`, which is built only by the tests that list it.

`MFAGuardSiteTitleExtension` is applied to SiteConfig only by `TOTPRegisterHandlerTest`, through its `required_extensions`. The issuer tests set the site title and read it back, but a project's own SiteConfig extensions may change the title on write, for example to keep it fixed in configuration. This extension runs after them and writes the title the test asked for, so the issuer tests run unchanged in such a project; every other SiteConfig write is left alone.

## The emulated browser and destroyed sessions

Functional tests emulate a browser through `Director::test()`, which copies `$_SESSION` back into the test session after each request, but only while `$_SESSION` is set. `Session::destroy()`, which every log-out calls, unsets it, and without a real PHP session nothing recreates it. A log-out would then be invisible to the test unless some other code in the project happened to rebuild `$_SESSION` later in the request.

`Tests\Support\DestroyedSessionMiddleware` closes that gap for the module's functional tests. It runs outermost and, when `$_SESSION` is no longer set after a request, sets it to whatever the request's session still holds: only values written after the destroy. A real browser behaves the same way, because `Session::destroy()` also ends the PHP session and expires its cookie. The middleware changes nothing for a session that survived the request, and `DestroyedSessionMiddlewareTest` checks both cases.

## Reaching the CMS in a project's own tests

A project's functional tests that log in with `logInAs()` or `logInWithPermission()` skip the MFA step, so the guard logs them out. Mark the test session as verified for that member instead of switching enforcement off:

```php
use Fromholdio\MFAGuard\Authenticators\MFALoginHandler;
use SilverStripe\Security\Security;

$this->logInWithPermission('ADMIN');
$this->session()->set(MFALoginHandler::SESSION_VERIFIED_MEMBER_ID, (int) Security::getCurrentUser()->ID);
```

The module's own `Tests\Support\MFASessionMarker` trait does exactly this, but a project's Composer autoloader cannot load it when PHPUnit loads the project's test classes, so keep a few lines like these in the project's own test support. If the project runs with `BYPASS_MFA` locally, also set `SilverStripe\MFA\Service\EnforcementManager.enabled` to `true` in the test's config so the guard is exercised.
