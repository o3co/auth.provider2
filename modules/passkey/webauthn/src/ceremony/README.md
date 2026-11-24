# ceremony

Internal module of `webauthn`: the WebAuthn ceremonies, over a pinned version of `@simplewebauthn/server`.

## Responsibilities
- Makes creation and request options, and verifies attestations and assertions.

## Not here
- Where challenges and credentials are kept, and which subject they belong to (the caller's).

## Offers
- `ceremoniesFor` (relying party) → the package's `Ceremonies`. No library type crosses it.
- Its `verifyAssertion`, the evidence check: the library's decoders and `parseAuthenticatorData` read what `assert` reads, and Node's crypto verifies the ES256 signature over the authenticator data and the client data's hash, at once.
- `algorithmNames`: the algorithms a credential may use (`EdDSA`, `ES256`, `RS256`), by the names `keys` gives them; the package's `algorithms` setting takes from them, all of them by default.
- `challengeOf` (response) → the challenge the client data names, read by the library's decoder, the one that verifies it.

## Invariants
- A challenge given that is not 32 bytes in their one unpadded base64url spelling is a `TypeError` (thrown, or the rejection of `attest` and `assert`); one that is goes into the options as it is. Verification other than `preferred` or `discouraged` is `required`. Options name no timeout, list the relying party's algorithms in its order, as COSE names them, ask for no attestation, and require a discoverable credential unless the caller asks for one that need not be.
- Before the library runs: client data the library cannot read is `malformed`; a challenge other than the one given is `challenge`; a reported top origin that is not listed, or not in a frame, is `top-origin`, and so is any frame when none is listed.
- The statement sent is dropped before the library reads it, and only `authData` is read, as a `none` attestation. An object that is not a map is `malformed`.
- The library's refusals map by how its messages start; any other is `malformed`. The library never judges the count (it is handed 0).
- After the signature: a handle carried must be the credential's (none carried passes only where the caller says the request named credentials, `named` being `true`), the backup eligibility must be the credential's, and the count must go up (0 after 0 passes).
- An assertion by a credential other than the one given is `malformed`; one by a key whose COSE algorithm is not the relying party's, or cannot be read, is `algorithm`, which the library does not check at assertion.

## Depends on
- `@simplewebauthn/server`; the package's contract
