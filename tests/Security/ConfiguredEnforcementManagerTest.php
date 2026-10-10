<?php

namespace Fromholdio\MFAGuard\Tests\Security;

use Fromholdio\MFAGuard\Services\ConfiguredEnforcementManager;
use Fromholdio\MFAGuard\Tests\Support\MFAEnforcementOn;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\Dev\SapphireTest;
use SilverStripe\MFA\Service\EnforcementManager;
use SilverStripe\ORM\FieldType\DBDatetime;
use SilverStripe\Security\Member;
use SilverStripe\SiteConfig\SiteConfig;

/**
 * MFA is required by config for every member with CMS access, with no grace
 * period, whatever the SiteConfig fields say; and isMFAEnforcedFor(), the
 * guard's one question, follows the module's own switches. setUp() switches
 * enforcement on (MFAEnforcementOn), so BYPASS_MFA in the .env does not change
 * the results.
 */
class ConfiguredEnforcementManagerTest extends SapphireTest
{
    use MFAEnforcementOn;

    protected static $fixture_file = 'MFATest.yml';

    protected function setUp(): void
    {
        parent::setUp();
        $this->enableMFAEnforcement();
    }

    protected function getManager(): EnforcementManager
    {
        return Injector::inst()->get(EnforcementManager::class);
    }

    protected function setSiteConfig(bool $isRequired, ?string $gracePeriodExpires): void
    {
        $siteConfig = SiteConfig::current_site_config();
        $siteConfig->MFARequired = $isRequired;
        $siteConfig->MFAGracePeriodExpires = $gracePeriodExpires;
        $siteConfig->write();
    }

    protected function getFutureDate(): string
    {
        return date('Y-m-d', DBDatetime::now()->getTimestamp() + 30 * 86400);
    }


    /**
     * Tests
     * ----------------------------------------------------
     */

    public function testTheInjectorResolvesTheConfiguredManager(): void
    {
        $this->assertInstanceOf(ConfiguredEnforcementManager::class, $this->getManager());
        $this->assertInstanceOf(ConfiguredEnforcementManager::class, EnforcementManager::singleton());
        $this->assertInstanceOf(ConfiguredEnforcementManager::class, EnforcementManager::create());
    }

    public function testMFAIsRequiredWithNoGracePeriodWhateverSiteConfigSays(): void
    {
        foreach ([[false, null], [false, $this->getFutureDate()], [true, $this->getFutureDate()], [true, null]] as [$isRequired, $grace])
        {
            $this->setSiteConfig($isRequired, $grace);
            $manager = $this->getManager();
            $this->assertTrue($manager->isMFARequired(), 'Required with SiteConfig ' . json_encode([$isRequired, $grace]));
            $this->assertFalse($manager->isGracePeriodInEffect(), 'No grace with SiteConfig ' . json_encode([$isRequired, $grace]));
        }
    }

    public function testACMSMemberCannotSkipEvenAfterSkippingBefore(): void
    {
        $this->setSiteConfig(false, $this->getFutureDate());
        $editor = $this->objFromFixture(Member::class, 'editor');
        $editor->HasSkippedMFARegistration = true;
        $editor->write();

        $this->assertTrue($this->getManager()->shouldRedirectToMFA($editor));
        $this->assertFalse($this->getManager()->canSkipMFA($editor));
    }

    public function testMFAIsEnforcedForEveryMemberWithCMSAccessOnly(): void
    {
        $manager = $this->getManager();
        $this->assertTrue($manager->isMFAEnforcedFor($this->objFromFixture(Member::class, 'admin')));
        $this->assertTrue($manager->isMFAEnforcedFor($this->objFromFixture(Member::class, 'editor')));
        $this->assertFalse($manager->isMFAEnforcedFor($this->objFromFixture(Member::class, 'public')));
    }

    /**
     * BYPASS_MFA sets enabled: false on the base class; the subclass inherits
     * it, so the guard stands down with the login flow.
     */
    public function testNothingIsEnforcedWhenTheModuleIsDisabled(): void
    {
        EnforcementManager::config()->set('enabled', false);
        $admin = $this->objFromFixture(Member::class, 'admin');

        $this->assertFalse($this->getManager()->isMFAEnforcedFor($admin));
        $this->assertFalse($this->getManager()->shouldRedirectToMFA($admin));
    }

    public function testNothingIsEnforcedWhenTheConfigSwitchIsOff(): void
    {
        ConfiguredEnforcementManager::config()->set('is_mfa_required', false);

        $this->assertFalse($this->getManager()->isMFARequired());
        $this->assertFalse($this->getManager()->isMFAEnforcedFor($this->objFromFixture(Member::class, 'admin')));
    }

    /**
     * Every member the guard enforces is also sent to MFA by the login, so the
     * guard never refuses a session the login would not have verified. Asserts
     * enforcement first, so it cannot pass with nothing enforced.
     */
    public function testEnforcementImpliesTheLoginFlowRedirectsToMFA(): void
    {
        $manager = $this->getManager();
        foreach (['admin', 'editor'] as $fixture)
        {
            $member = $this->objFromFixture(Member::class, $fixture);
            $this->assertTrue($manager->isMFAEnforcedFor($member), $fixture . ' is enforced');
            $this->assertTrue($manager->shouldRedirectToMFA($member), $fixture . ' is sent to MFA');
        }
        $this->assertFalse($manager->isMFAEnforcedFor($this->objFromFixture(Member::class, 'public')), 'public is not enforced');
    }
}
