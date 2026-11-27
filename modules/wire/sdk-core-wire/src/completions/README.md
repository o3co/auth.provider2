# completions

Internal module of `sdk-core-wire`: the completions the Core seals to the screen beside the authorization's, and how passkey-add's and passkey-manage's are padded before they are sealed.

## Responsibilities
- Holds the schemas of passkey-add's, passkey-manage's and a key change's completion.
- Holds their padding: the buckets, the bounds a completion fits its bucket within, padding one and reading it back.

## Not here
- The authorization's completion, the sealing's suite, info and additional data (`completionAad`), a continuation's bodies, the label and the other building blocks: the package's.
- Sealing, opening, signing and verifying: each side's.

## Offers
- `completions`: `passkeyAdd`, `passkeyManage` and `keyChange`, which the package offers as `payloads.completions`.
- `padding`: `buckets`, `limits`, `padded` and `unpadded`, which the package offers as `hpke`'s `completionBuckets`, `completionLimits`, `paddedCompletion` and `unpaddedCompletion`.

## Invariants
- passkey-add's completion carries the continued `creation`; passkey-manage's, the keys' list; a key change (§C.5), its `change`, and at the log's level its `receipt`, `status` and `stateOf` (F1's under `sign-up` too).
- A list names what it answers where it answers a continuation (`continued`: stage, sequence, the body's hash its continuation signs): a rename's, or a delete's the Core did not take; the approval's names none. A list holds each credential once, 16 at most, each row's `created_at` in seconds (a JWT's NumericDate).
- A delete not taken says why (`refused`: `last`, no key would be left; `used`, this approval deleted one already; `unknown`, no active key of the person's by that id), sealed in the padded list, so the Front sees neither the reason nor a count. A delete taken is answered by its key change. A key change adds under `first-key`, `passkey-add` or `sign-up`, deletes under `passkey-manage`.
- A padded completion (a delete's too) is bucketed by the person's longest credential ID alone, for a delete taken its list before it, the deleted key among them, for one not taken the list it carries, the ID asked not counted; the smaller where all are 128 bytes or less: it tells only if some ID is longer, never the count, the labels or the key deleted.
- At L0 each fits its bucket within `limits` (issuer URL 256 characters, `kid` 128, RSA 8192 bits) and the Core's items at their owners' bounds (a subject of 255 visible ASCII characters, a passkey-add's account a masked address of 257 bytes, an RP id of 253), a quote in the issuer or subject written in two by JSON; one that does not fit its bucket is not sealed. The log's `status` and `stateOf` have no bound yet, so L1 sets one before they are padded.
- A padded completion is its compact JWS then spaces, read back only at a bucket's length.

## Depends on
- The package's `primitives` (the version, ids, hashes, the label, a compact JWS, a set's signed text), `zod`.
