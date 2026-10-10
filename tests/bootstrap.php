<?php

/**
 * PHPUnit bootstrap for running this module's tests from a host project.
 *
 * Composer loads autoload-dev only for the root package, so a project that
 * requires this module cannot autoload Fromholdio\MFAGuard\Tests\ on its
 * own, and PHPUnit loads the test classes (and their base classes) before
 * Silverstripe's class manifest is available. This file registers that
 * namespace with the project's Composer autoloader, then hands over to the
 * framework's own test bootstrap.
 *
 * The project root is the working directory PHPUnit is started from, or
 * MFA_GUARD_PROJECT_ROOT when that is set.
 */

$projectRoot = getenv('MFA_GUARD_PROJECT_ROOT') ?: getcwd();
$autoloadPath = rtrim((string) $projectRoot, DIRECTORY_SEPARATOR) . '/vendor/autoload.php';
$frameworkBootstrapPath = rtrim((string) $projectRoot, DIRECTORY_SEPARATOR) . '/vendor/silverstripe/framework/tests/bootstrap.php';

if (!is_file($autoloadPath) || !is_file($frameworkBootstrapPath))
{
    fwrite(STDERR, sprintf(
        "Run these tests from the root of a Silverstripe project with fromholdio/silverstripe-mfa-guard installed,"
        . " or set MFA_GUARD_PROJECT_ROOT. Looked for %s and %s.\n",
        $autoloadPath,
        $frameworkBootstrapPath
    ));
    exit(1);
}

$loader = require $autoloadPath;
$loader->addPsr4('Fromholdio\\MFAGuard\\Tests\\', __DIR__ . '/');

require $frameworkBootstrapPath;
