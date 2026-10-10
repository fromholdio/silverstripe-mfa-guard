<?php

namespace Fromholdio\MFAGuard\Tests\Fixtures;

use SilverStripe\Core\Extension;
use SilverStripe\Dev\TestOnly;
use SilverStripe\SiteConfig\SiteConfig;

/**
 * Lets a test set the site title in a project whose own SiteConfig
 * extensions change the title on write, for example to keep a title fixed in
 * configuration. A test asks for a title by holding it on the record as
 * dynamic data under REQUESTED_TITLE, then writes the record as usual; this
 * hook applies that title. Writes without a requested title are untouched.
 *
 * A test adds it through $required_extensions, which appends it after the
 * extensions the project configures on SiteConfig, so its onBeforeWrite()
 * runs after theirs and the requested title is the one written. Only tests
 * that list it apply it, so it never changes a project's SiteConfig outside
 * those tests.
 *
 * @extends Extension<SiteConfig>
 */
class MFAGuardSiteTitleExtension extends Extension implements TestOnly
{
    /**
     * The dynamic data key holding the title a test asks for.
     */
    public const REQUESTED_TITLE = 'MFAGuardTestRequestedTitle';


    /**
     * Hooks
     * ----------------------------------------------------
     */

    protected function onBeforeWrite(): void
    {
        $title = $this->owner->getDynamicData(self::REQUESTED_TITLE);
        if (is_null($title))
        {
            return;
        }
        $this->owner->Title = $title;
    }
}
