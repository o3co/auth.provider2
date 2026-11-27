# parent

Internal module of `authority-rules`: a passkey-add's approving key, as its creation names it (V30, FIX_ADD_PARENT).

## Responsibilities
- Tells whether the key a passkey-add's creation names as its approving key (`approver_key`) is the record's parent: the key the monitor verified the passkey-add's assertion by. That it is the screen's own is the screen's check (login-screen's `assertion`).

## Not here
- Where the record sits, the parent's liveness and its assertion, the creation's basis, subject, key generation and E keys: `chain`, which asks it. How the key's form and thumbprint are spelled: `passkey-key-wire`.

## Offers
- `approverRefusal` (the caller's checks, the parent's key as the flow holds it, the key the creation names) → why not, or none.

## Invariants
- The key named is the parent by thumbprint: passkey-key-wire's `passkeyThumbprintInput` of the JWK named, digested, against `keyThumbprint` of the parent's key. A credential id binds nothing here, being the registering side's to choose.
- A parent whose key does not read approves none; a creation naming no key of a passkey's form is refused (sdk-core-wire takes no passkey-add's creation with none, but holds the key to its members' spellings alone, not to passkey-key-wire's whole form).
- An RS256 parent approves no passkey-add in 0.1.0: no binding against duplicate-signature key selection is shown for RSA, so the screen could not tell its own key from another, and refusing it closes that case by itself. Once e = 65537's binding is shown, taking one is a wire change first (sdk-core-wire holds `approver_key` to P-256 and Ed25519).
- Checking the screen's own assertion under the named key is the model's equality check because a key goes live only with its own possession proof; for ECDSA another key verifies the same signature, but no one holds its private key.

## Depends on
- `passkey-key-wire` (the key's form); the package's `evidence` (`Checks`).
