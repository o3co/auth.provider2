# assertion

Internal module of `login-screen`: the screen's own assertion, verified under a key a creation names (V30, FIX_ADD_PARENT).

## Responsibilities
- Tells whether the screen's own approving assertion is the `get()` for its statement and verifies under the key a passkey-add's creation names as its approving key.

## Not here
- When to ask and what an answer means: `management`, which asks it before the creation goes on. The key's form: `sdk-core-wire` (`approver_key`).

## Offers
- `verifiedUnder` (the assertion's bytes as the screen sent them, the key named, the statement's get challenge) → `verified`, `unverified` or `unsupported`.

## Invariants
- It reads the assertion in WebAuthn's `toJSON()` form (§5.1.10): client data of type `webauthn.get`, its challenge the statement's, and a signature over the authenticator data and the SHA-256 of the client data's bytes as sent (§7.2 step 20), by WebCrypto alone.
- ES256's signature is DER read strictly: one SEQUENCE of two shortest positive INTEGERs, each in [1, n−1]. Ed25519's is its 64 bytes, verified by WebCrypto's Ed25519 (S canonical, no key of small order taking an honest signature).
- What does not read or import, and any failure, is `unverified`; a key type this browser cannot import (Ed25519 without WebCrypto's) is `unsupported`, which may be honest: there the screen cannot tell its own Ed25519 key from another, and both refuse. The signature's form is read first, so an assertion of another type than the key named is `unverified`, never `unsupported`.
- Verifying its own assertion under the named key is the model's equality check because a key goes live only with its own possession proof: for ECDSA another key (Q*) verifies the same signature, and only the holder of the original key can derive its private key, so no attacker can make Q*'s possession.

## Depends on
- `sdk-core-wire` (`ApproverKey`'s form); the package's `bytes`.
