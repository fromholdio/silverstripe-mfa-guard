<?php

namespace Fromholdio\MFAGuard\Tests\Support;

use Closure;
use Fromholdio\MFAGuard\Authenticators\MFALoginHandler;
use Fromholdio\MFAGuard\Authenticators\TOTPRegisterHandler;
use OTPHP\TOTP;
use SilverStripe\Control\Director;
use SilverStripe\Control\HTTPResponse;
use SilverStripe\Core\Environment;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\Dev\FunctionalTest;
use SilverStripe\Security\Member;
use SilverStripe\Security\Security;

/**
 * Base of the CMS MFA functional tests. Each test walks the real login: the
 * password form, then the MFA module's JSON endpoints under
 * Security/login/default/mfa, exactly as its React app calls them. Redirects
 * are never followed automatically: the tests assert them.
 *
 * The tests act as the authenticator app. The registration endpoint returns
 * the TOTP secret as "code"; getTotpCode() computes the current code from it
 * with OTPHP\TOTP, the library the module verifies with. The module calls
 * verify() with no leeway, so only the current 30-second window is accepted,
 * and the helper waits for a fresh window when fewer than
 * MIN_WINDOW_SECONDS remain, so a slow step cannot carry a code across the
 * boundary.
 *
 * SS_MFA_SECRET_KEY and FIO_MFA_ISSUER_NAME are set in setUp() so the tests
 * do not depend on the project's .env; the test state restores the
 * environment after each test. setUp() also switches MFA enforcement on
 * (MFAEnforcementOn), so BYPASS_MFA in the .env cannot switch off what the
 * tests check, and puts DestroyedSessionMiddleware outermost on the
 * Director, so a session the guard or session-manager destroys is lost by
 * the emulated browser as it is by a real one. CSRF tokens are disabled by
 * FunctionalTest.
 */
abstract class MFAFunctionalTestCase extends FunctionalTest
{
    use MFAEnforcementOn;
    use MFASessionMarker;
    use PasswordFormFields;

    protected $autoFollowRedirection = false;

    protected const MFA_SECRET_KEY = 'mfa-guard-test-secret-key-not-for-production';

    protected const ISSUER_NAME = 'MFA Guard test issuer';

    /**
     * Every fixture member's password.
     */
    protected const PASSWORD = 'Correct-Horse-Battery-2026';

    protected const MFA_URL = 'Security/login/default/mfa';

    protected const MIN_WINDOW_SECONDS = 5;

    protected function setUp(): void
    {
        parent::setUp();
        Environment::setEnv('SS_MFA_SECRET_KEY', self::MFA_SECRET_KEY);
        Environment::setEnv(TOTPRegisterHandler::ENV_ISSUER_NAME, self::ISSUER_NAME);
        $this->enableMFAEnforcement();
        $this->addDestroyedSessionMiddleware();
    }

    /**
     * Registers a copy of the Director with DestroyedSessionMiddleware in
     * front of every other middleware. The copy is registered on this test's
     * nested Injector, so the Director other tests resolve is untouched.
     */
    protected function addDestroyedSessionMiddleware(): void
    {
        $director = clone Injector::inst()->get(Director::class);
        $director->setMiddlewares(
            ['MFAGuardTestDestroyedSession' => DestroyedSessionMiddleware::create()]
            + (array) $director->getMiddlewares()
        );
        Injector::inst()->registerService($director, Director::class);
    }


    /**
     * Browser
     * ----------------------------------------------------
     */

    /**
     * A new browser: the test session emptied, as after closing the window.
     * The session is cleared in place rather than replaced, because each
     * TestSession pushes a controller that its destructor unwinds.
     */
    protected function startFreshBrowser(): void
    {
        $this->session()->clearAll();
        Security::setCurrentUser(null);
    }

    /**
     * Puts the current browser aside: its session data, to hand back to
     * restoreBrowser() later, so one test can hold several browsers (one
     * member on two devices, say). Session data is all a browser carries
     * here, because "Keep me signed in" is off and no other cookie decides who
     * is logged in.
     */
    protected function saveBrowser(): array
    {
        return (array) $this->session()->getAll();
    }

    /**
     * Switches back to a browser saved with saveBrowser(): the test session
     * is emptied, as in startFreshBrowser(), then refilled with that
     * browser's session data. Its next request is that browser's next
     * request.
     */
    protected function restoreBrowser(array $browser): void
    {
        $this->startFreshBrowser();
        foreach ($browser as $name => $value)
        {
            $this->session()->set($name, $value);
        }
    }

    /**
     * The password step: load the login form and submit it.
     */
    protected function submitPassword(string $email, string $password = self::PASSWORD, ?string $backURL = null): HTTPResponse
    {
        $url = 'Security/login';
        if (!is_null($backURL))
        {
            $url .= '?BackURL=' . urlencode($backURL);
        }
        $this->get($url);
        return $this->submitForm('MemberLoginForm_LoginForm', null, [
            'Email' => $email,
            'Password' => $password,
            'action_doLogin' => 1,
        ]);
    }

    protected function getJSON(string $url): array
    {
        $response = $this->get($url);
        $this->assertSame(200, $response->getStatusCode(), $url . ' answered ' . $response->getStatusCode() . ': ' . $response->getBody());
        return (array) json_decode((string) $response->getBody(), true);
    }

    protected function postJSON(string $url, array $body): HTTPResponse
    {
        return $this->post($url, [], ['Content-Type' => 'application/json'], null, json_encode($body));
    }

    protected function getLocation(HTTPResponse $response): string
    {
        return (string) $response->getHeader('Location');
    }

    protected function assertRedirectsToMFA(HTTPResponse $response): void
    {
        $this->assertSame(302, $response->getStatusCode());
        $this->assertStringEndsWith(self::MFA_URL, $this->getLocation($response));
    }

    protected function getSessionMarker(): ?int
    {
        $value = $this->session()->get(MFALoginHandler::SESSION_VERIFIED_MEMBER_ID);
        return is_null($value) ? null : (int) $value;
    }

    protected function getLoggedInMemberID(): ?int
    {
        $value = $this->session()->get('loggedInAs');
        return is_null($value) ? null : (int) $value;
    }


    /**
     * Authenticator app
     * ----------------------------------------------------
     */

    /**
     * The current code for a base32 secret, from a window with at least
     * MIN_WINDOW_SECONDS left.
     */
    protected function getTotpCode(string $secret): string
    {
        $totp = TOTP::createFromSecret($secret);
        $remaining = $totp->expiresIn();
        if ($remaining < self::MIN_WINDOW_SECONDS)
        {
            sleep($remaining + 1);
        }
        return $totp->now();
    }

    /**
     * A six-digit code that is not the current one for this secret.
     */
    protected function getWrongTotpCode(string $secret): string
    {
        $code = $this->getTotpCode($secret);
        return str_pad((string) (((int) $code + 1) % 1000000), 6, '0', STR_PAD_LEFT);
    }


    /**
     * Flows
     * ----------------------------------------------------
     */

    /**
     * Starts TOTP registration after the password step and returns the start
     * response: code (the secret), uri (the provisioning URI) and the rest.
     */
    protected function startTotpRegistration(): array
    {
        return $this->getJSON(self::MFA_URL . '/register/totp');
    }

    /**
     * The whole first sign-in of an unenrolled member: password, TOTP
     * registration with a computed code, then the backup codes. Returns the
     * secret and the backup codes, and leaves the member logged in.
     */
    protected function enroll(Member $member, ?string $backURL = null): array
    {
        $this->assertRedirectsToMFA($this->submitPassword($member->Email, self::PASSWORD, $backURL));

        $start = $this->startTotpRegistration();
        $secret = (string) $start['code'];
        $finish = $this->postJSON(self::MFA_URL . '/register/totp', ['code' => $this->getTotpCode($secret)]);
        $this->assertSame(201, $finish->getStatusCode(), (string) $finish->getBody());

        $backup = $this->getJSON(self::MFA_URL . '/register/backup-codes');
        $codes = (array) ($backup['codes'] ?? []);
        $this->assertNotEmpty($codes, 'Backup codes are issued after the first method');
        $done = $this->postJSON(self::MFA_URL . '/register/backup-codes', []);
        $this->assertSame(201, $done->getStatusCode(), (string) $done->getBody());

        return ['secret' => $secret, 'backupCodes' => $codes];
    }

    /**
     * A second sign-in with an enrolled method: password, then one code
     * posted to the method's verify endpoint. Returns the verify response.
     *
     * A time-based code must be passed as a closure that computes it: the
     * closure runs only after the password step and the verify start, just
     * before the post, so those requests cannot carry a code computed earlier
     * across its 30-second window. A static code, such as a backup code, can
     * be passed as a string.
     */
    protected function signInWithCode(string $email, string $segment, string|Closure $code): HTTPResponse
    {
        $this->assertRedirectsToMFA($this->submitPassword($email));
        $this->getJSON(self::MFA_URL . '/verify/' . $segment);
        $value = $code instanceof Closure ? $code() : $code;
        return $this->postJSON(self::MFA_URL . '/verify/' . $segment, ['code' => $value]);
    }
}
