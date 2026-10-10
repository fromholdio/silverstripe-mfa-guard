<?php

namespace Fromholdio\MFAGuard\Tests\Security;

use SilverStripe\Dev\SapphireTest;
use SilverStripe\Forms\CompositeField;
use SilverStripe\Forms\Tab;
use SilverStripe\SiteConfig\SiteConfig;

/**
 * Settings > Access no longer offers the MFA toggle or its grace-period date,
 * and no empty "Multi-factor authentication" group heading is left behind;
 * the Access tab itself and its other fields stay.
 */
class SiteConfigMFAExtensionTest extends SapphireTest
{
    protected $usesDatabase = true;

    public function testTheMFAFieldsAndTheirGroupAreGoneFromSettings(): void
    {
        $fields = SiteConfig::current_site_config()->getCMSFields();

        $this->assertNull($fields->dataFieldByName('MFARequired'));
        $this->assertNull($fields->dataFieldByName('MFAGracePeriodExpires'));

        $tab = $fields->findTab('Root.Access');
        $this->assertInstanceOf(Tab::class, $tab, 'The Access tab stays');
        $this->assertNotNull($fields->dataFieldByName('CanViewType'), 'The page permissions stay');

        foreach ($tab->getChildren() as $field)
        {
            if ($field instanceof CompositeField)
            {
                $this->assertGreaterThan(0, $field->getChildren()->count(), 'No empty group is left on the Access tab');
            }
            $this->assertStringNotContainsString('Multi-factor authentication', (string) $field->Title());
        }
    }
}
