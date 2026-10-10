<?php

namespace Fromholdio\MFAGuard\Authenticators;

use SilverStripe\Core\Environment;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\MFA\Store\StoreInterface;
use SilverStripe\Security\Member;
use SilverStripe\Security\Security;
use SilverStripe\TOTP\Method;
use SilverStripe\TOTP\RegisterHandler;
use UnexpectedValueException;

/**
 * silverstripe/totp-authenticator's register handler with the issuer, the
 * name authenticator apps show for this site, taken from the
 * FIO_MFA_ISSUER_NAME environment variable. Installed by an Injector
 * replacement of SilverStripe\TOTP\RegisterHandler in _config/mfa.yml; the
 * TOTP Method builds its handler with Injector::inst()->create(), so the
 * replacement governs the login enrolment and the CMS profile's "Reset"
 * alike.
 *
 * Why a replacement and not an extension. The TOTP module's start() sets the
 * issuer to the SiteConfig title and only then fires updateTotp. otphp
 * validates the issuer inside setIssuer() and its TOTP class is final, so a
 * site title containing a colon throws InvalidLabelException before any
 * extension runs, and enrolment fails even with a valid variable. The issuer
 * must be chosen before anything reaches otphp, which only start() itself
 * can do.
 *
 * - Set: start() validates the trimmed value through getIssuerName() first,
 *   then builds the TOTP exactly as the TOTP module does except that the
 *   SiteConfig title never reaches setIssuer().
 * - Unset or empty: parent::start() runs untouched, so the TOTP module's
 *   default (the SiteConfig title) stays, with its own behaviour for it.
 * - Containing a colon: getIssuerName() throws, naming the variable, before
 *   a secret is generated. otphp rejects a colon (literal or %3A) because
 *   it separates the issuer from the account in the URI label.
 *
 * Only the issuer changes; the account label stays the member's unique
 * identifier, and updateTotp still fires for any extension. The issuer is
 * baked into the QR code at enrolment, so changing the variable later does
 * not rename entries already in anyone's app. The name is deliberately not
 * TOTP-specific, so another MFA method could use it as its own display or
 * relying-party name.
 *
 * Upstream drift. The set path of start() is derived from
 * RegisterHandler::start() in silverstripe/totp-authenticator 6.1.1
 * (BSD-3-Clause, copyright Silverstripe Ltd.; see THIRD-PARTY-NOTICES.md)
 * with one line changed. If a later release changes start() (another key in
 * the returned array, different secret handling, a new hook), this copy will
 * not follow it. TOTPRegisterHandlerTest fingerprints the installed
 * module's start() and fails when it changes, and asserts that both paths
 * return the same keys, so an upgrade cannot drift silently: re-read the
 * TOTP module's start(), bring this copy into line, then update the
 * fingerprint.
 */
class TOTPRegisterHandler extends RegisterHandler
{
    /**
     * The environment variable carrying the issuer name.
     */
    public const ENV_ISSUER_NAME = 'FIO_MFA_ISSUER_NAME';


    /**
     * Core
     * ----------------------------------------------------
     */

    public function start(StoreInterface $store): array
    {
        $issuer = static::getIssuerName();
        if (is_null($issuer))
        {
            return parent::start($store);
        }

        // From RegisterHandler::start() in totp-authenticator 6.1.1; only the
        // setIssuer() argument differs.
        $store->setState([
            'secret' => $this->generateSecret(),
        ]);

        $totp = $this->getTotp($store);

        $member = $store->getMember() ?: Security::getCurrentUser();
        if (!is_null($member))
        {
            $uniqueIdentifier = (string) Member::config()->get('unique_identifier_field');
            $totp->setLabel($member->{$uniqueIdentifier});
        }
        $totp->setIssuer($issuer);

        $this->extend('updateTotp', $totp, $member);

        return [
            'enabled' => !empty(Environment::getEnv('SS_MFA_SECRET_KEY')),
            'uri' => $totp->getProvisioningUri(),
            'code' => $totp->getSecret(),
            'codeLength' => Injector::inst()->create(Method::class)->getCodeLength(),
        ];
    }


    /**
     * Getters
     * ----------------------------------------------------
     */

    /**
     * The issuer name from the environment, trimmed, or null when it is unset
     * or empty.
     *
     * @throws UnexpectedValueException when the value contains a colon, in
     * either its literal or its URL-encoded form, both of which otphp rejects
     */
    public static function getIssuerName(): ?string
    {
        $value = trim((string) Environment::getEnv(self::ENV_ISSUER_NAME));
        if ($value === '')
        {
            return null;
        }
        if (str_contains($value, ':') || stripos($value, '%3A') !== false)
        {
            throw new UnexpectedValueException(sprintf(
                'The %s environment variable must not contain a colon; authenticator apps use the colon to'
                . ' separate the issuer from the account name. Current value: "%s".',
                self::ENV_ISSUER_NAME,
                $value
            ));
        }
        return $value;
    }
}
