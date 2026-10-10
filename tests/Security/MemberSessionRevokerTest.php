<?php

namespace Fromholdio\MFAGuard\Tests\Security;

use Fromholdio\MFAGuard\Services\MemberSessionRevoker;
use SilverStripe\Dev\SapphireTest;
use SilverStripe\ORM\FieldType\DBDatetime;
use SilverStripe\Security\Member;
use SilverStripe\Security\RememberLoginHash;
use SilverStripe\SessionManager\Models\LoginSession;

/**
 * MemberSessionRevoker deletes one member's LoginSession and
 * RememberLoginHash rows, reports how many of each, and touches no other
 * row: not another member's, and not an unlinked row a member that has not
 * been written yet (ID 0) would otherwise match. The functional tests in
 * MFAResetSessionsTest and MFAResetTaskTest show that deleting the rows
 * logs each browser out.
 */
class MemberSessionRevokerTest extends SapphireTest
{
    protected static $fixture_file = 'MFATest.yml';


    /**
     * Helpers
     * ----------------------------------------------------
     */

    protected function createLoginSession(int $memberID): LoginSession
    {
        $loginSession = LoginSession::create();
        $loginSession->MemberID = $memberID;
        $loginSession->LastAccessed = DBDatetime::now()->Rfc2822();
        $loginSession->IPAddress = '192.0.2.10';
        $loginSession->UserAgent = 'MemberSessionRevokerTest';
        $loginSession->Persistent = false;
        $loginSession->write();
        return $loginSession;
    }

    protected function createRememberLoginHash(int $memberID): RememberLoginHash
    {
        $hash = RememberLoginHash::create();
        $hash->MemberID = $memberID;
        $hash->DeviceID = bin2hex(random_bytes(20));
        $hash->Hash = bin2hex(random_bytes(32));
        $hash->ExpiryDate = date('Y-m-d H:i:s', DBDatetime::now()->getTimestamp() + 14 * 86400);
        $hash->write();
        return $hash;
    }

    protected function getCounts(int $memberID): array
    {
        return [
            'loginSessions' => LoginSession::get()->filter('MemberID', $memberID)->count(),
            'rememberLoginHashes' => RememberLoginHash::get()->filter('MemberID', $memberID)->count(),
        ];
    }


    /**
     * Tests
     * ----------------------------------------------------
     */

    public function testItRemovesOneMembersRowsAndReportsTheCounts(): void
    {
        $editor = $this->objFromFixture(Member::class, 'editor');
        $other = $this->objFromFixture(Member::class, 'othereditor');
        $this->createLoginSession((int) $editor->ID);
        $this->createLoginSession((int) $editor->ID);
        $this->createRememberLoginHash((int) $editor->ID);
        $this->createLoginSession((int) $other->ID);
        $this->createRememberLoginHash((int) $other->ID);
        $this->createLoginSession(0);

        $result = MemberSessionRevoker::singleton()->revokeAllSessions($editor);

        $this->assertSame(['loginSessions' => 2, 'rememberLoginHashes' => 1], $result);
        $this->assertSame(['loginSessions' => 0, 'rememberLoginHashes' => 0], $this->getCounts((int) $editor->ID));
        $this->assertSame(['loginSessions' => 1, 'rememberLoginHashes' => 1], $this->getCounts((int) $other->ID));
        $this->assertSame(1, LoginSession::get()->filter('MemberID', 0)->count(), 'An unlinked row is not touched');
    }

    public function testASecondRunFindsNothing(): void
    {
        $editor = $this->objFromFixture(Member::class, 'editor');
        $this->createLoginSession((int) $editor->ID);

        MemberSessionRevoker::singleton()->revokeAllSessions($editor);
        $result = MemberSessionRevoker::singleton()->revokeAllSessions($editor);

        $this->assertSame(['loginSessions' => 0, 'rememberLoginHashes' => 0], $result);
    }

    public function testAMemberNotYetWrittenEndsNothing(): void
    {
        $this->createLoginSession(0);
        $this->createRememberLoginHash(0);

        $result = MemberSessionRevoker::singleton()->revokeAllSessions(Member::create());

        $this->assertSame(['loginSessions' => 0, 'rememberLoginHashes' => 0], $result);
        $this->assertSame(['loginSessions' => 1, 'rememberLoginHashes' => 1], $this->getCounts(0));
    }
}
