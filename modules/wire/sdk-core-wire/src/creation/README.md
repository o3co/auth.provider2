# creation

Internal module of `sdk-core-wire`: a creation statement's items, what a `create()` is for.

## Responsibilities
- Holds the creation's items schema: the account it shows, its basis and evidence, its subject and key generation, the key that approved a passkey-add, and webauthn's options it names.

## Not here
- The statement around the items (the common fields, the nonce, the purpose), the label and the other building blocks: the package's.
- A passkey's key form, its thumbprint's input: `passkey-key-wire`.

## Offers
- `items`, which the package's `payloads.creation` carries as its `creation`.

## Invariants
- A creation names its account by `account` or `user_name`, one alone: the first key's path by `account`, F1's by `user_name` (its subject has none), passkey-add's by either. `user_name` is a label's text, not blank.
- Its `basis` fixes what its evidence hashes: the mail token (`first-key`), the approved `passkey-add` statement, or the T read before signing up (`sign-up`); `ct_hash` is `first-key`'s alone, a creation with no basis read as such.
- It excludes 15 credentials at most, and names the `algorithms` the ceremony offered, as COSE numbers them, each once.
- It names the key generation it is signed for (`kg`): one signed before a reset registers no key after it.
- `approver_key` (V30) is passkey-add's alone, optional until the Core names it on every passkey-add, then required: the key whose approval it goes on from, the record's parent and the screen's own, as a P-256 or Ed25519 JWK. Here, it is held to its members and spellings alone. Each reader reads it through passkey-key-wire, where a value of no passkey's form has no thumbprint.
- An RSA key approves no passkey-add in 0.1.0 (no binding against duplicate-signature key selection is shown), so it is no approver here; taking one is a wire change.

## Depends on
- The package's `primitives` (`label`); `zod`.
