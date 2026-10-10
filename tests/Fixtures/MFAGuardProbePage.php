<?php

namespace Fromholdio\MFAGuard\Tests\Fixtures;

use SilverStripe\CMS\Model\SiteTree;
use SilverStripe\Dev\TestOnly;

/**
 * A versioned page for the guard's draft and archive tests, so they need no
 * page class or theme from the host project. MFAGuardProbePageController
 * answers with the page's Content alone.
 *
 * The test kernel scans every module's tests directory, so this class is in
 * any host project's test manifest. Its namespaced class name and its
 * MFAGuardTest_ table prefix keep it clear of a host's own classes and
 * tables; only tests that list it in extra_dataobjects build its table.
 */
class MFAGuardProbePage extends SiteTree implements TestOnly
{
    private static string $table_name = 'MFAGuardTest_ProbePage';

    private static string $controller_name = MFAGuardProbePageController::class;

    private static bool $can_be_root = true;
}
