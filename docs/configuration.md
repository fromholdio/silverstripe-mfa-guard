# Configuration

The module works with no project configuration beyond the environment variables in the [README](../README.md#environment-variables). This page describes what its three config fragments set, the few settings a project can change, and how to order a project's own config against them.

## The supported profile

The module supports one policy: MFA is mandatory for every member with CMS access, with no grace period. It is not a general MFA policy framework.

- `Fromholdio\MFAGuard\Services\ConfiguredEnforcementManager.is_mfa_required` is `true`. Setting it to `false` switches the requirement and the session guard off together. It does not make MFA optional in a guarded way: the MFA module may still ask enrolled members for a code at the login, while other ways of becoming logged in are no longer checked. Optional MFA is not a supported configuration.
- `SilverStripe\MFA\Service\EnforcementManager.requires_admin_access` stays at the MFA module's default of `true`, so MFA applies to members with access to any part of the CMS and not to members without it.
- The MFA module's own `enabled` setting is respected. `BYPASS_MFA` sets it to `false`, which turns off both the MFA step and the guard. The module never sets `enabled` itself, so it cannot defeat that switch.

## What the fragments set

### `_config/mfa.yml` (`mfaguard`)

Ordered after the MFA and TOTP modules' fragments `#mfa-authenticator`, `#mfa-siteconfig`, `#mfa-memberextension` and `#totpauthenticatorconfig`.

- **Injector replacements**, listed below.
- **`ConfiguredEnforcementManager.is_mfa_required: true`**.
- **`CMSSecurity.reauth_enabled: false`**: the CMS's password-only re-login popup is off.
- **`SiteConfig` extension `mfaGuardSiteConfigExtension`**: hides the MFA module's "MFA is optional / required" field and grace-period date, which no longer control anything. The database columns stay because the MFA module owns them.
- **`SecurityExtension` extension `mfaGuardAccountResetSessionExtension`**: ends every session of a member who completes an account reset, after the MFA module's own extension has removed their methods.

### `_config/middleware.yml` (`mfaguard-middleware`)

Registers `MFASessionGuardMiddleware` on the Director as `MFASessionGuardMiddleware`, ordered `After: '#coresecurity'` and `Before: '#versionedrequestprocessors'`. The framework's `AuthenticationMiddleware` has therefore resolved the member before the guard runs, and `VersionedHTTPMiddleware` and the controllers run after it, so they see a logged-out member as an anonymous visitor.

### `_config/security.yml` (`mfaguard-security`)

Sets `Security.autologin_enabled: false`, ordered `After: '#coresecurity'` and `After: '#fiobundle-foundation-security'`. The second entry keeps "keep me signed in" off on sites that also install `fromholdio/bundle-foundation`, whose security fragment switches it on; it has no effect where that fragment is absent.

## Injector replacements

| Service | Replaced by | Why |
| --- | --- | --- |
| `SilverStripe\MFA\Service\EnforcementManager` | `Fromholdio\MFAGuard\Services\ConfiguredEnforcementManager` | The requirement comes from config, not SiteConfig, and the guard asks it whether a member must have passed MFA. |
| `SilverStripe\MFA\Authenticator\LoginHandler` | `Fromholdio\MFAGuard\Authenticators\MFALoginHandler` | One password check per submission, and the session marker written when MFA completes. |
| `SilverStripe\MFA\Authenticator\ChangePasswordHandler` | `Fromholdio\MFAGuard\Authenticators\MFAChangePasswordHandler` | The bound, throttled code check on a forgotten-password reset. |
| `SilverStripe\TOTP\RegisterHandler` | `Fromholdio\MFAGuard\Authenticators\TOTPRegisterHandler` | The issuer from `FIO_MFA_ISSUER_NAME`. |

These replacements work as a set. The guard throws a `LogicException` when the enforcement manager it resolves is not a `ConfiguredEnforcementManager`, rather than guessing. If another module replaces any of these services, or adds a way of establishing a logged-in member outside the login form (single sign-on, an API token authenticator, a custom password handler), that combination needs its own integration and tests; it is not covered automatically.

To confirm the resolved classes on a site, run the module's test suite there (see [testing.md](testing.md)); `MFAGuardConfigurationTest` checks each replacement.

## The session marker

When a member completes MFA, `MFALoginHandler` stores their ID in the session under `MFALoginHandler::SESSION_VERIFIED_MEMBER_ID`. The guard admits a logged-in member only when that value is their own ID. `MFALoginHandler::getVerifiedMemberID()` reads it for a request. A forgotten-password reset records its own bound verification under `MFAChangePasswordHandler::SESSION_VERIFIED_RESET` until the new password is set. Both are ordinary session values, removed when the session ends.

## Guard settings

`Fromholdio\MFAGuard\Middleware\MFASessionGuardMiddleware.guarded_path_prefixes` lists the first URL segments that are redirected to the login after an unverified member is logged out. The default is `admin` and `dev`. The list does not limit protection: an unverified member is logged out on every request, and on other paths the request simply continues anonymously.

```yaml
Fromholdio\MFAGuard\Middleware\MFASessionGuardMiddleware:
  guarded_path_prefixes:
    - admin
    - dev
    - my-members-area
```

An XHR request to a guarded prefix gets a 403 "Not logged in" response instead of a redirect, so the CMS shows a message rather than rendering the login page inside a panel.

## Ordering a project's own config

Use the fragment names above in `Before` and `After` rather than relying on load order.

- **A middleware that must wrap the guard**, for example one that adds security headers to every response including the guard's redirects, belongs before it: `Before: '#mfaguard-middleware'`.
- **A middleware that needs the guard's decision**, for example one that reads the current member for authorisation, belongs after it: `After: '#mfaguard-middleware'`.
- **A project that wants "keep me signed in" back** has to load after `#mfaguard-security`. Doing so reopens a path that skips the second factor at sign-in; the guard will then log those sessions out on their first request, so members would see it as a broken checkbox.

## Recovery task options

`tasks:mfa-reset` has two options, `--email` and `--keep-password`, described in [recovery.md](recovery.md#break-glass-tasksmfa-reset). It cannot run in a browser.
