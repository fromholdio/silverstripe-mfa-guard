# Third-party notices

This package includes code adapted from the following third-party works. Each section says where its licence text comes from: reproduced from the upstream package, or assembled by this package where the upstream publishes no licence file.

## restruct/silverstripe-mfa-bundle

- **Used in:** `src/Authenticators/MFALoginHandler.php`, the single password check per login submission (`doLogin()`, `checkLogin()` and the stored check result).
- **Source:** `src/Authenticator/SingleCheckLoginHandler.php` in [restruct/silverstripe-mfa-bundle](https://github.com/restruct/silverstripe-mfa-bundle) 1.6.0 (commit `5036ffab10e3c602b9bb6c7cd7fd3baa2c80979a`).
- **Licence:** MIT, as declared in the `license` field of that package's `composer.json` and in its README's "License" section, which reads only "MIT". The `composer.json` `authors` field names Restruct (https://restruct.nl).
- **Licence text source:** the upstream repository has no licence or notice file at that tag, and neither its README nor the adapted source file carries a copyright line. The text below is therefore not reproduced from upstream: it is the standard MIT licence text, assembled by this package, with the copyright line taken from the upstream `authors` metadata. No copyright year is given because the upstream states none.

```text
MIT License

Copyright (c) Restruct (https://restruct.nl)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## silverstripe/totp-authenticator

- **Used in:** `src/Authenticators/TOTPRegisterHandler.php`, the body of `start()` when `FIO_MFA_ISSUER_NAME` is set.
- **Source:** `RegisterHandler::start()` in `src/RegisterHandler.php` of [silverstripe/totp-authenticator](https://github.com/silverstripe/silverstripe-totp-authenticator) 6.1.1.
- **Licence:** BSD 3-Clause.
- **Licence text source:** reproduced verbatim from the `LICENSE` file distributed with `silverstripe/totp-authenticator` 6.1.1.

```text
Copyright (c) 2019, Silverstripe Ltd.
All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```
