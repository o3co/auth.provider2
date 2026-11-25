# webauthn

## Responsibilities
- Runs WebAuthn ceremonies for its relying party: options, response verification, the signature count and the user handle, by its internal module `ceremony`.
- Owns the form of a credential and of a user handle that ceremonies take and answer.

## Not here
- Keeping passkeys and their subjects (`passkeys`). Making a challenge, keeping it, judging its lifetime, and what an assertion leads to (the caller's). Issuing tokens.

## Offers
- `ceremonies`: creation options (a discoverable credential unless asked otherwise) and attestation, request options and assertion, each over a challenge the caller gives. The caller keeps the challenge and credential, judges how long the challenge is answerable, and hands them over once. `challengeOf` reads the challenge a response answers: the client's value, so a caller hands the ceremonies only a challenge it matched against its own record.
  - The user verification asked is an argument of each call: `preferred` and `discouraged` weaken it; any other, none included, is `required`.
  - `verifyAssertion(assertion, publicKey, challenge, origin)` (authority-rules' `Checks.verifyAssertion`), at once, against no credential state: an assertion response's JSON as a browser serializes it, and the key's COSE_Key in base64url, of any algorithm a passkey may be of (ES256, EdDSA, RS256) whatever `algorithms` offers.
  - `verifyAssertion` answers the assertion's credential id where `assert` requiring verification would take it for that challenge and origin (the one given, which `origins` must list; backed up without backup eligibility refused, as `assert` refuses it), reading no count, backup state or handle; else none, never a throw.
  - `reverifyAssertion(assertion, publicKey, challenge)`: the same check, one function, at a rooted refresh, for an approval's assertion: for whichever of `origins` its client data names.
  - `attestedKey(response)` (authority-rules' `Checks.attestedKey`): a `create()` response's credential id and new key (COSE_Key, base64url), as `attest` reads them, the key whole; never verified; none where it does not read.
  - `allowsOrigin(origin)`: whether `origins` lists it, as ceremonies match.
  - `assert` takes the challenge with `named`, whether the request named credentials: the caller's own record of its request, never a value the client sent. Only `true` is named.
- `keyThumbprint` (a COSE_Key, base64url): its thumbprint, the SHA-256 of passkey-key-wire's `passkeyThumbprintInput`, and its algorithm as COSE numbers it; none for a key not in passkey-key-wire's one COSE_Key form, or off its curve.
- `credentialOf`: a value read as a credential in the shape webauthn writes, with its fields alone and the canonical checks and limits of its id, key and handle (`isCanonical`, `credentialLimits`); nothing for any other. `freshHandle`: a new user handle from the randomness given, by webauthn's own rule.
- Operator section: `rp-id`, `rp-name`, `origins` (required), `top-origins` (default none), `algorithms` (some of `ES256`, `EdDSA` and `RS256`, each once; default `["ES256", "EdDSA"]`; any other refuses boot at `webauthn.algorithms` or the entry).
  - `algorithms` narrows creation's offer and attestation alone; `verifyAssertion` and `keyThumbprint` read all three, so a past record judges the same after it changes. Naming RS256 warns `webauthn.rs256_offered` at every start: a 2048-bit RSA key holds about 112-bit security, signs by PKCS#1 v1.5, and FAPI 2.0 forbids it.
- `./testing`: `webauthnConfig`, a configuration builder (origin `testOrigin`), the ceremonies over a relying party a test gives (`testCeremonies`), a software authenticator behind a browser (`softwareAuthenticator`), answering as a browser does, with twists for refusals; `statingCertificate`, the twist of an attestation stating a certificate.

## Invariants
- A challenge is 32 bytes in their one unpadded base64url spelling, used as given: the options ask it to be signed, and a response must answer it. Any other value given is the caller's `TypeError`, before anything is asked or read: `creation` and `request` throw it, `attest` and `assert` reject with it. No challenge is made, kept or timed here, and options name no timeout.
- Origins match the list exactly: https, or http on `localhost` (refused at boot in production); never an IP literal. An Android app origin is `android:apk-key-hash:` and the unpadded base64url SHA-256 of its signing certificate, never a top origin. A relying party ID that is a public suffix of several labels (`co.uk`) passes boot: no list of them is kept, and the browser refuses it at the first ceremony.
- An origin that is empty or no URL refuses boot at its place in the list. A reported top origin not listed is refused, and with none listed any frame is, for registration and assertion alike; every start with some listed warns `webauthn.framed_by_other_origins`, by their count. The relying party ID must match; boot refuses one that is not each web origin's host or a domain it lies under.
- A new credential's algorithm is one of `algorithms`: creation offers them, and an attestation by a key of another is `algorithm`. A new key not in passkey-key-wire's one COSE_Key form, the very bytes the authenticator data holds, with nothing after them but one map of extensions where flagged, is `malformed`. `assert` takes a kept key of any algorithm a passkey may be of, and one not in that form is `algorithm`.
- The count is compared after the signature verified, and must go up (0 after 0 passes).
- An assertion whose request named no credential (`named` false) is refused without a user handle (`user-handle`, WebAuthn §7.2 step 6); one whose request named it may carry none. A handle carried must be the credential's.
- A user handle is 32 random bytes, carrying neither the subject nor a name. Handles and credential ids are compared only as unpadded base64url. Transports are taken only as a short list of short strings.
- Creation asks for no attestation, so it takes the public key as sent: nothing proves the client holds its private key until the first assertion. The statement sent is dropped before the library reads it, and only `authData` is read, as a `none` attestation. `required` refuses a response without user verification. A backup eligibility other than the credential's is refused.

## Data
- None: the caller keeps the challenges and the credentials.

## Depends on
- `kernel`, `passkey-key-wire` (the key form)
