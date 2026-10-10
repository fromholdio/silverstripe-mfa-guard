<?php

namespace Fromholdio\MFAGuard\Extensions;

use SilverStripe\Core\Extension;
use SilverStripe\Forms\CompositeField;
use SilverStripe\Forms\FieldList;
use SilverStripe\Forms\Tab;
use SilverStripe\Forms\TabSet;

/**
 * Hides the MFA toggle silverstripe/mfa adds to Settings > Access.
 *
 * ConfiguredEnforcementManager takes the MFA requirement from config and
 * never reads SiteConfig's MFARequired or MFAGracePeriodExpires, so the MFA
 * module's "MFA is optional / required" choice and its grace-period date
 * would offer a switch that does nothing. This extension removes both
 * fields, then removes the group the MFA module wraps them in (an unnamed
 * CompositeField whose title is the "Multi-factor authentication (MFA)"
 * heading) if that left it empty, so no orphan heading remains.
 *
 * It never removes a Tab or TabSet: the fields are removed as data fields
 * only, and the container is removed only when it is a plain CompositeField,
 * so the Access tab and its page permissions stay.
 *
 * The two database columns stay, because the MFA module owns them; they are
 * simply no longer read. Applied after the MFA module's own extension in
 * _config/mfa.yml, so its fields exist by the time this hook runs.
 */
class SiteConfigMFAExtension extends Extension
{
    /**
     * The MFA module's SiteConfig fields this extension removes.
     */
    private static array $removed_mfa_field_names = [
        'MFARequired',
        'MFAGracePeriodExpires',
    ];


    /**
     * CMS Fields
     * ----------------------------------------------------
     */

    protected function updateCMSFields(FieldList $fields): void
    {
        $names = (array) $this->owner->config()->get('removed_mfa_field_names');
        $containers = [];
        foreach ($names as $name)
        {
            $field = $fields->dataFieldByName($name);
            if (is_null($field))
            {
                continue;
            }
            $container = $field->getContainerFieldList()?->getContainerField();
            if ($container instanceof CompositeField && !($container instanceof Tab) && !($container instanceof TabSet))
            {
                $containers[] = $container;
            }
            $fields->removeByName($name, true);
        }

        foreach ($containers as $container)
        {
            if ($container->getChildren()->count() > 0)
            {
                continue;
            }
            $container->getContainerFieldList()?->remove($container);
        }
    }
}
