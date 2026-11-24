# webauthn

## Responsibilities
- Runs WebAuthn ceremonies for its relying party: options, response verification, the signature count and the user handle, by its internal module `ceremony`.
- Owns the form of a credential and of a user handle that ceremonies take and answer.

## Not here
- Keeping passkeys and their subjects (`passkeys`). Making a challenge, keeping it and judging its lifetime (the caller's). What an assertion leads to (the caller's). Issuing tokens.

## Offers
- `ceremonies`: creation options (a discoverable credential unless asked otherwise) and attestation, request options and assertion, each over a challenge the caller gives. The caller keeps the challenge and the credential, judges how long the challenge can be answered, and hands them over once. `challengeOf` reads the challenge a response answers: the client's value, so a caller hands the ceremonies only a challenge it matched against its own record.
  - The user verification asked is an argument of each call: `preferred` and `discouraged` weaken it, and any other value, none included, is `required`.
  - `verifyAssertion(assertion, publicKey, challenge, origin)` (authority-rules' `Checks.verifyAssertion`), at once and against no credential state: `assertion` the JSON of an assertion response as a browser serializes it, `publicKey` an uncompressed P-256 point in base64url (ES256 alone, while `algorithms` takes it).
  - `verifyAssertion` answers the assertion's credential id where `assert` requiring verification would take it for that challenge and origin (one origin, as given), reading no count, backup state or handle; none otherwise, never a throw.
  - `assert` takes the challenge with `named`, whether the request named credentials: the caller's own record of its request, never a value the client sent. Only `true` is named.
- `credentialOf`: a value read as a credential in the shape webauthn writes, with its fields alone and the canonical checks and limits of its id, key and handle (`isCanonical`, `credentialLimits`); nothing for any other value. `freshHandle`: a new user handle from the randomness given, by the rule webauthn makes its own by.
- Operator section: `rp-id`, `rp-name`, `origins` (required), `top-origins` (default none), `algorithms` (`EdDSA`, `ES256`, `RS256`, at least one, each once; default all three).
- `./testing`: `webauthnConfig`, a test configuration builder with the origin `testOrigin`, the ceremonies over a relying party a test gives (`testCeremonies`), and a software authenticator behind a browser (`softwareAuthenticator`), which answers options as a browser does and takes twists for refusal tests; `statingCertificate` is the twist of an attestation stating a certificate.

## Invariants
- A challenge is 32 bytes in their one unpadded base64url spelling, used as given: the options ask it to be signed, and a response must answer it. Any other value given is the caller's `TypeError`, before anything is asked or read: `creation` and `request` throw it, `attest` and `assert` reject with it. No challenge is made, kept or timed here, and options name no timeout.
- Origins match the list exactly: https, or http on `localhost` (refused at boot in production); never an IP literal. An Android app origin is `android:apk-key-hash:` and the unpadded base64url SHA-256 of its signing certificate, never a top origin. A relying party ID that is a public suffix of several labels (`co.uk`) passes boot: no list of them is kept, and the browser refuses it at the first ceremony.
- An origin that is empty or no URL refuses boot at its place in the list. A reported top origin not listed is refused, and with none listed any frame is, for registration and assertion alike; every start with some listed warns `webauthn.framed_by_other_origins`, by their count. The relying party ID must match; boot refuses one that is not each web origin's host or a domain it lies under.
- A credential's algorithm is one of `algorithms`: creation offers them in their order, and an attestation or an assertion by a key of another is `algorithm`. Leaving one out makes the passkeys made with it unusable, the operator's choice; their users register another.
- The count is compared after the signature verified, and must go up (0 after 0 passes).
- An assertion whose request named no credential (`named` false) is refused without a user handle (`user-handle`, WebAuthn §7.2 step 6); one whose request named it may carry none. A handle carried must be the credential's.
- A user handle is 32 random bytes, carrying neither the subject nor a name. Handles and credential ids are compared only as unpadded base64url. Transports are taken only as a short list of short strings.
- Creation asks for no attestation, so it takes the public key as sent: nothing proves the client holds its private key until the first assertion. The statement sent is dropped before the library reads it, and only `authData` is read, as a `none` attestation. `required` refuses a response without user verification. A backup eligibility other than the credential's is refused.

## Data
- None: the caller keeps the challenges and the credentials.

## Depends on
- `kernel`
