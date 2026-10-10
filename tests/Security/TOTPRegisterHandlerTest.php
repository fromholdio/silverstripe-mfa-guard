<?php

namespace Fromholdio\MFAGuard\Tests\Security;

use Fromholdio\MFAGuard\Authenticators\TOTPRegisterHandler;
use Fromholdio\MFAGuard\Tests\Fixtures\MFAGuardSiteTitleExtension;
use Fromholdio\MFAGuard\Tests\Support\MFAFunctionalTestCase;
use OTPHP\Exception\InvalidLabelException;
use ReflectionMethod;
use SilverStripe\Core\Environment;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\Security\Member;
use SilverStripe\Security\SudoMode\SudoModeServiceInterface;
use SilverStripe\SiteConfig\SiteConfig;
use SilverStripe\TOTP\RegisterHandler;
use UnexpectedValueException;

/**
 * The name authenticator apps show is FIO_MFA_ISSUER_NAME when it is set,
 * whatever the site title holds; the module default (the SiteConfig title)
 * when it is not; and a colon in the variable fails with a message naming
 * it. The account label stays the member's email throughout. Read from the
 * provisioning URI the registration endpoints return, which is what the QR
 * code carries, on both the login enrolment and the CMS profile's reset.
 *
 * TOTPRegisterHandler copies the module's start() for the set path, so this
 * test also fingerprints the installed start() and compares the two paths'
 * returned keys: an upgrade that changes start() fails here rather than
 * drifting silently.
 */
class TOTPRegisterHandlerTest extends MFAFunctionalTestCase
{
    protected static $fixture_file = 'MFATest.yml';

    protected static $required_extensions = [
        SiteConfig::class => [
            MFAGuardSiteTitleExtension::class,
        ],
    ];

    /**
     * SHA-256 of RegisterHandler::start() in silverstripe/totp-authenticator
     * 6.1.1, the method TOTPRegisterHandler::start() copies.
     */
    protected const UPSTREAM_START_SHA256 = '66c12572c5fb60808ded65c30962004950616911198d79cf112638b57f904f3f';

    /**
     * Sets the site title the way an administrator does, writing SiteConfig
     * through the ORM, and reads it back to prove it took: from the database,
     * and from SiteConfig::current_site_config(), where the TOTP module reads
     * it. MFAGuardSiteTitleExtension applies the title after the project's own
     * SiteConfig write hooks, so a project that fixes the title on write runs
     * these tests too. A project that changes the title some other way fails
     * here, naming the cause, rather than in the issuer assertions.
     */
    protected function setSiteTitle(string $title): void
    {
        $siteConfig = SiteConfig::current_site_config();
        $siteConfig->Title = $title;
        $siteConfig->setDynamicData(MFAGuardSiteTitleExtension::REQUESTED_TITLE, $title);
        $siteConfig->write();
        $this->assertSame(
            $title,
            SiteConfig::get()->byID($siteConfig->ID)?->Title,
            'The site title was written; this project changes SiteConfig titles after its write hooks'
        );
        $this->assertSame(
            $title,
            SiteConfig::current_site_config()->Title,
            'The site title took; this project changes SiteConfig titles after its write hooks'
        );
    }

    protected function parseProvisioningURI(string $uri): array
    {
        $this->assertStringStartsWith('otpauth://totp/', $uri);
        $parts = parse_url($uri);
        parse_str((string) ($parts['query'] ?? ''), $query);
        return [
            'label' => rawurldecode(ltrim((string) $parts['path'], '/')),
            'query' => $query,
        ];
    }

    /**
     * The password step for the editor, then the TOTP registration start on
     * the login; returns the start response.
     */
    protected function startLoginRegistration(): array
    {
        $editor = $this->objFromFixture(Member::class, 'editor');
        $this->assertRedirectsToMFA($this->submitPassword($editor->Email));
        return $this->startTotpRegistration();
    }


    /**
     * Tests
     * ----------------------------------------------------
     */

    public function testTheInjectorResolvesTheHandler(): void
    {
        $this->assertInstanceOf(TOTPRegisterHandler::class, Injector::inst()->create(RegisterHandler::class));
    }

    public function testTheIssuerIsTheEnvironmentValue(): void
    {
        Environment::setEnv(TOTPRegisterHandler::ENV_ISSUER_NAME, '  Example CMS staging  ');

        $parts = $this->parseProvisioningURI((string) $this->startLoginRegistration()['uri']);

        $this->assertSame('Example CMS staging', $parts['query']['issuer']);
        $this->assertSame('Example CMS staging:casey.editor@example.com', $parts['label']);
    }

    /**
     * The TOTP module sets the SiteConfig title as the issuer before any
     * hook runs, so without the replacement a colon in the title breaks
     * enrolment even with a valid variable.
     */
    public function testAValidVariableWinsOverASiteTitleWithAColon(): void
    {
        Environment::setEnv(TOTPRegisterHandler::ENV_ISSUER_NAME, 'Example CMS staging');
        $this->setSiteTitle('Example site: review');

        $start = $this->startLoginRegistration();
        $parts = $this->parseProvisioningURI((string) $start['uri']);

        $this->assertSame('Example CMS staging', $parts['query']['issuer']);
        $this->assertSame('Example CMS staging:casey.editor@example.com', $parts['label']);
        $this->assertStringNotContainsString('review', (string) $start['uri']);

        $finish = $this->postJSON(self::MFA_URL . '/register/totp', ['code' => $this->getTotpCode((string) $start['code'])]);
        $this->assertSame(201, $finish->getStatusCode(), 'The registration completes');
    }

    /**
     * The same on the CMS side: "Reset" on the authenticator app in My
     * Profile registers through the module's admin endpoint.
     */
    public function testTheProfileResetUsesTheVariableToo(): void
    {
        Environment::setEnv(TOTPRegisterHandler::ENV_ISSUER_NAME, 'Example CMS staging');
        $this->setSiteTitle('Example site: review');
        $editor = $this->objFromFixture(Member::class, 'editor');
        $this->logInAs($editor);
        $this->markSessionMFAVerified();
        Injector::inst()->get(SudoModeServiceInterface::class)->activate($this->session());

        $start = $this->getJSON('admin/mfa/register/totp');
        $parts = $this->parseProvisioningURI((string) $start['uri']);

        $this->assertSame('Example CMS staging', $parts['query']['issuer']);
        $this->assertSame('Example CMS staging:casey.editor@example.com', $parts['label']);
    }

    public function testAnUnsetVariableKeepsTheModuleDefault(): void
    {
        Environment::setEnv(TOTPRegisterHandler::ENV_ISSUER_NAME, '');
        $this->setSiteTitle('Example site');

        $parts = $this->parseProvisioningURI((string) $this->startLoginRegistration()['uri']);

        $this->assertSame('Example site', $parts['query']['issuer']);
        $this->assertSame('Example site:casey.editor@example.com', $parts['label']);
        $this->assertNull(TOTPRegisterHandler::getIssuerName());
    }

    /**
     * The boundary of "unset keeps the module default": the module's own
     * behaviour for a colon in the title is unchanged, and nothing here
     * rewrites the title into an issuer. Setting the variable is the remedy.
     */
    public function testAnUnsetVariableLeavesTheModuleBehaviourForAColonTitle(): void
    {
        Environment::setEnv(TOTPRegisterHandler::ENV_ISSUER_NAME, '');
        $this->setSiteTitle('Example site: review');
        $editor = $this->objFromFixture(Member::class, 'editor');
        $this->assertRedirectsToMFA($this->submitPassword($editor->Email));

        $this->expectException(InvalidLabelException::class);
        $this->get(self::MFA_URL . '/register/totp');
    }

    public function testAColonInTheVariableFailsNamingIt(): void
    {
        foreach (['Example: staging', 'Example%3Astaging', 'Example%3astaging'] as $value)
        {
            Environment::setEnv(TOTPRegisterHandler::ENV_ISSUER_NAME, $value);
            try
            {
                TOTPRegisterHandler::getIssuerName();
                $this->fail('A colon must be refused: ' . $value);
            }
            catch (UnexpectedValueException $exception)
            {
                $this->assertStringContainsString(TOTPRegisterHandler::ENV_ISSUER_NAME, $exception->getMessage());
                $this->assertStringContainsString('colon', $exception->getMessage());
            }
        }
    }

    /**
     * Both values bad: the variable's own message wins, because it is checked
     * before the title can reach otphp.
     */
    public function testAColonInTheVariableStopsRegistrationBeforeAnyQRCodeIsIssued(): void
    {
        Environment::setEnv(TOTPRegisterHandler::ENV_ISSUER_NAME, 'Example: staging');
        $this->setSiteTitle('Example site: review');
        $editor = $this->objFromFixture(Member::class, 'editor');
        $this->assertRedirectsToMFA($this->submitPassword($editor->Email));

        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage(TOTPRegisterHandler::ENV_ISSUER_NAME);
        $this->get(self::MFA_URL . '/register/totp');
    }

    public function testBothPathsReturnTheSameKeys(): void
    {
        Environment::setEnv(TOTPRegisterHandler::ENV_ISSUER_NAME, 'Example CMS staging');
        $set = $this->startLoginRegistration();

        $this->startFreshBrowser();
        Environment::setEnv(TOTPRegisterHandler::ENV_ISSUER_NAME, '');
        $unset = $this->startLoginRegistration();

        $this->assertSame(array_keys($unset), array_keys($set));
        $this->assertSame($unset['codeLength'], $set['codeLength']);
        $this->assertSame($unset['enabled'], $set['enabled']);
    }

    /**
     * The tripwire for upgrades: TOTPRegisterHandler::start() copies this
     * method for the set path. When this fails, re-read the module's start(),
     * bring the copy into line, then update UPSTREAM_START_SHA256.
     */
    public function testTheModulesStartIsTheVersionTheCopyFollows(): void
    {
        $method = new ReflectionMethod(RegisterHandler::class, 'start');
        $lines = array_slice(
            file((string) $method->getFileName()),
            $method->getStartLine() - 1,
            $method->getEndLine() - $method->getStartLine() + 1
        );

        $this->assertSame(
            self::UPSTREAM_START_SHA256,
            hash('sha256', implode('', $lines)),
            'silverstripe/totp-authenticator RegisterHandler::start() has changed; bring TOTPRegisterHandler::start() into line with it'
        );
    }
}
