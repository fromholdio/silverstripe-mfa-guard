<?php

namespace Fromholdio\MFAGuard\Tests\Security;

use Fromholdio\MFAGuard\Authenticators\MFAChangePasswordHandler;
use Fromholdio\MFAGuard\Authenticators\MFALoginHandler;
use Fromholdio\MFAGuard\Authenticators\TOTPRegisterHandler;
use Fromholdio\MFAGuard\Extensions\SiteConfigMFAExtension;
use Fromholdio\MFAGuard\Services\ConfiguredEnforcementManager;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\Dev\SapphireTest;
use SilverStripe\MFA\Authenticator\MemberAuthenticator;
use SilverStripe\MFA\Service\EnforcementManager;
use SilverStripe\SiteConfig\SiteConfig;
use SilverStripe\TOTP\RegisterHandler;
use Symfony\Component\Yaml\Yaml;

/**
 * The module's configuration as a whole: the four Injector replacements
 * resolve, the SiteConfig extension is applied, and each fragment declares
 * its order against the fragments it must follow or precede, rather than
 * relying on where a project happens to load it. The resolved middleware
 * order and the settings these fragments produce are asserted in
 * MFASessionGuardMiddlewareTest and MFAResetSessionsTest.
 */
class MFAGuardConfigurationTest extends SapphireTest
{
    protected $usesDatabase = false;

    /**
     * The header of the module's config fragment in the given file: Name,
     * Before and After.
     */
    protected function getFragmentHeader(string $file): array
    {
        $path = dirname(__DIR__, 2) . '/_config/' . $file;
        $this->assertFileExists($path);
        $parts = preg_split('/^---\s*$/m', (string) file_get_contents($path));
        return (array) Yaml::parse((string) ($parts[1] ?? ''));
    }

    protected function getList(array $header, string $key): array
    {
        return array_values((array) ($header[$key] ?? []));
    }


    /**
     * Tests
     * ----------------------------------------------------
     */

    public function testTheInjectorReplacementsResolve(): void
    {
        $authenticator = new MemberAuthenticator();
        $this->assertInstanceOf(ConfiguredEnforcementManager::class, Injector::inst()->get(EnforcementManager::class));
        $this->assertInstanceOf(MFALoginHandler::class, $authenticator->getLoginHandler('Security/login/default'));
        $this->assertInstanceOf(MFAChangePasswordHandler::class, $authenticator->getChangePasswordHandler('Security/changepassword'));
        $this->assertInstanceOf(TOTPRegisterHandler::class, Injector::inst()->create(RegisterHandler::class));
    }

    public function testTheSiteConfigExtensionIsApplied(): void
    {
        $this->assertTrue(SiteConfig::has_extension(SiteConfigMFAExtension::class));
    }

    public function testTheMFAFragmentFollowsTheModulesItReplaces(): void
    {
        $header = $this->getFragmentHeader('mfa.yml');

        $this->assertSame('mfaguard', $header['Name'] ?? null);
        foreach (['#mfa-authenticator', '#mfa-siteconfig', '#mfa-memberextension', '#totpauthenticatorconfig'] as $fragment)
        {
            $this->assertContains($fragment, $this->getList($header, 'After'), 'mfa.yml follows ' . $fragment);
        }
    }

    public function testTheGuardFragmentSitsBetweenAuthenticationAndVersioning(): void
    {
        $header = $this->getFragmentHeader('middleware.yml');

        $this->assertSame('mfaguard-middleware', $header['Name'] ?? null);
        $this->assertContains('#coresecurity', $this->getList($header, 'After'));
        $this->assertContains('#versionedrequestprocessors', $this->getList($header, 'Before'));
    }

    /**
     * fromholdio/bundle-foundation switches autologin on in
     * #fiobundle-foundation-security; the module must load after it where it
     * is installed. The After entry has no effect where it is not.
     */
    public function testTheSecurityFragmentFollowsTheFragmentsThatEnableAutologin(): void
    {
        $header = $this->getFragmentHeader('security.yml');

        $this->assertSame('mfaguard-security', $header['Name'] ?? null);
        $this->assertContains('#coresecurity', $this->getList($header, 'After'));
        $this->assertContains('#fiobundle-foundation-security', $this->getList($header, 'After'));
    }
}
