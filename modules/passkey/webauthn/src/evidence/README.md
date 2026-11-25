# evidence

Internal module of `webauthn`: the checks of a passkey's evidence at once, against no credential state, as the transparency rules and a rooted refresh ask them.

## Responsibilities
- Verifies an assertion by the key given, and reads a `create()` response's credential and new key, reading what the ceremonies read and keeping nothing.

## Not here
- The interactive ceremonies, their options and their count, handle and backup state (`ceremony`). Reading a response's client data, frame and new key (`reading`). What the rules make of an answer (`authority-rules`).

## Offers
- `evidenceCheck` (relying party) → the check `Ceremonies.verifyAssertion` and `reverifyAssertion` answer by; `attestedKey` (response) → `Ceremonies.attestedKey`.
  - `verifyAssertion(assertion, publicKey, challenge, origin)` (authority-rules' `Checks.verifyAssertion`), at once, against no credential state: an assertion response's JSON as a browser serializes it, and the key's COSE_Key in base64url, of any algorithm a passkey may be of (ES256, EdDSA, RS256) whatever `algorithms` offers.
  - `verifyAssertion` answers the assertion's credential id where `assert` requiring verification would take it for that challenge and origin (the one given, which `origins` must list; backed up without backup eligibility refused, as `assert` refuses it), reading no count, backup state or handle; else none, never a throw.
  - `reverifyAssertion(assertion, publicKey, challenge)`: the same check, one function, at a rooted refresh, for an approval's assertion: for whichever of `origins` its client data names.
  - `attestedKey(response)` (authority-rules' `Checks.attestedKey`): a `create()` response's credential id and new key (COSE_Key, base64url), as `attest` reads them, the key whole; never verified; none where it does not read.
- The evidence check: the library's decoders and `parseAuthenticatorData` read what `assert` reads, and Node's crypto verifies the signature over the authenticator data and the client data's hash, at once, by the key's algorithm (EdDSA, ES256 or RS256) whatever the relying party offers.

## Depends on
- `@simplewebauthn/server` (its decoders alone); the package's key reading and `reading`.
