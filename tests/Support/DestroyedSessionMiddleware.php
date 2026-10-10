<?php

namespace Fromholdio\MFAGuard\Tests\Support;

use SilverStripe\Control\HTTPRequest;
use SilverStripe\Control\HTTPResponse;
use SilverStripe\Control\Middleware\HTTPMiddleware;
use SilverStripe\Core\Injector\Injectable;
use SilverStripe\Dev\TestOnly;

/**
 * Lets a functional test's emulated browser lose a session that was
 * destroyed during a request, as a real browser does.
 *
 * Director::test() starts each request with $_SESSION set to the test
 * session's data, and afterwards copies $_SESSION back into the test session,
 * but only while $_SESSION is set. Session::destroy(), which every log-out
 * through the IdentityStore calls, unsets $_SESSION; it is the only code in
 * the framework that does. Without a real PHP session nothing recreates it,
 * even when the request writes to the session again afterwards (the
 * session-manager log-out handler does, clearing its own key), so nothing
 * is copied back and the test session keeps the member logged in. A real
 * browser has lost that session: destroy() also ends the PHP session and
 * expires its cookie. Whether a test passed would then depend on whether
 * some unrelated code in the host project happened to rebuild $_SESSION
 * after the log-out.
 *
 * This middleware runs outermost, after SessionMiddleware has saved. When
 * $_SESSION is no longer set, the session was destroyed during the request,
 * and it sets $_SESSION to what the request's session still holds: nothing
 * from before the destroy, which emptied it, and only what was written
 * afterwards, as a real browser would carry in the fresh session the
 * framework starts for those writes. Director::test() then removes every
 * other key from the test session. A request whose session was not destroyed
 * leaves $_SESSION set, and this middleware changes nothing; nothing outside
 * tests uses it.
 */
class DestroyedSessionMiddleware implements HTTPMiddleware, TestOnly
{
    use Injectable;

    public function process(HTTPRequest $request, callable $delegate): ?HTTPResponse
    {
        try
        {
            return $delegate($request);
        }
        finally
        {
            if (!isset($_SESSION))
            {
                $_SESSION = $this->getDataWrittenAfterDestroy($request);
            }
        }
    }

    /**
     * What the request's session holds once destroyed: only values written
     * after Session::destroy(), which set its data to null.
     */
    protected function getDataWrittenAfterDestroy(HTTPRequest $request): array
    {
        if (!$request->hasSession())
        {
            return [];
        }
        return (array) $request->getSession()->getAll();
    }
}
