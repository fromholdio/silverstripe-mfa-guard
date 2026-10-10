# Contributor guidance

This package is `fromholdio/silverstripe-mfa-guard`, with the PHP namespace `Fromholdio\MFAGuard\`.

## Scope and security

- Keep changes focused on mandatory CMS MFA, verified sessions and account recovery.
- Verify Silverstripe APIs against the installed supported versions before changing classes or configuration.
- Preserve security regression coverage when refactoring authentication, session handling or recovery.
- Use synthetic accounts and a disposable test host for runtime verification.
- Edit this package checkout directly, rather than a consuming application's vendor directory.

## Code style

- Use Allman braces, explicit parameter and return types, affirmative boolean names and `is_null()`.
- Use snake_case for configuration keys and US English for code identifiers.
- Use Australian English for prose and avoid hard-wrapped Markdown paragraphs.
- Separate class types into corresponding directories and namespaces.

## Documentation and distribution

- Keep all shipped documentation, comments, examples and fixtures suitable for a public audience.
- Avoid personal references, private filesystem paths, client-specific assumptions and internal project history.
- Preserve required third-party copyright and licence notices.
- Document supported dependency versions and reproducible verification commands without claiming untested compatibility.
- Do not include secrets, generated credentials or environment-specific configuration.

## Collaborative work

Respect assigned file ownership and preserve other contributors' changes. Report test results and unresolved concerns accurately.
