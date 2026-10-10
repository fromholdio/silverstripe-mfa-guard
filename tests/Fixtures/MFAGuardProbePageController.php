<?php

namespace Fromholdio\MFAGuard\Tests\Fixtures;

use SilverStripe\CMS\Controllers\ContentController;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Control\HTTPResponse;
use SilverStripe\Dev\TestOnly;

/**
 * Renders MFAGuardProbePage as its Content and nothing else, so the tests can
 * read which version of the page a request was given without a template.
 * ContentController::init() still runs, with its permission check.
 */
class MFAGuardProbePageController extends ContentController implements TestOnly
{
    public function index(HTTPRequest $request): HTTPResponse
    {
        return HTTPResponse::create((string) $this->dataRecord->Content);
    }
}
