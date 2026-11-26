# passkey-completion

Internal module of `approvals`: a passkey-add's and a passkey-manage's completions, padded so their length tells nothing of the keys.

## Responsibilities
- Signs, pads and seals a passkey-add's completion and a passkey-manage's (the subject's keys, or a delete's key change), and keeps each with its record; refuses boot where the settings would make one not fit.

## Not here
- The keys themselves and their list: `passkeys`. A delete's deciding: `passkey-management`'s key change. A key change's completion: `key-change-completion`.

## Offers
- `passkeyManageCompletionsOver` (with passkeys' `listOf`) → `completePasskeyManage` (a used passkey-manage's hash and its assertion, `make` to make one; or a continuation's `continued`): the subject's keys (label or `Passkey` and its day; time in seconds); a delete's key change.
- `passkeyAddCompletionsOver` → `completePasskeyAdd` (a used passkey-add's hash, the assertion that used it as received, and, to make one, the creation its caller made for it): the `passkeyAdd` completion carrying that creation.
- `beyondLimits` (issuer, Core keys' JWKs) → why one passes the wire's completion limits.
- `completionLimitsChecked` (the build context): refuses boot by `beyondLimits`, asked by its package before the other internal modules' parts. `passkeyCompletionOf` (the build context) → `completePasskeyAdd` and `completePasskeyManage`; `passkeyCompletionTakes`, which its package names among its own takes.

## Invariants
- A passkey-add's completion is made only for a passkey-add used by the same assertion, unexpired, that this generation's ring verifies, and a creation issued here for it: basis `passkey-add`, its hash as evidence, the subject that used it, the same screen's keys (else `creation`).
- It is signed, padded to the bucket its creation's longest excluded credential ID chooses (`paddedCompletion`; one not fitting is `form`, never sealed), and sealed under `completionAad` of `passkey-add` and its hash before anything is kept, then kept whole in one write from used: the first kept is answered to every call after, with or without a creation, whatever has lapsed since. Made twice at once, one creation is lost.
- Boot is refused where the issuer, or a Core key's kid or RSA modulus, passes `sdk-core-wire`'s `completionLimits` (`beyondLimits`): a completion then fails by settings, never by one person's keys.
- A passkey-manage's completion is padded as a passkey-add's, to the bucket its keys' longest credential ID chooses. The approval's is made only on `make` (its caller checked the approving key), for the assertion that used it, and kept only unexpired, read in the write; else the kept one alone. A continuation's only for the number and body its record took and holds unanswered, under a live hold of its step, up to the record's end, kept by its step.
- A delete's continuation is answered, both padded by the longest ID kept as its number was taken, or longer now; taken: by its key change (the key its body's hash names, the log's receipt alone); not: by the list, `continued` naming it and why (`last`, `used`, `unknown`). One answer per number, its step's, kept by `continueSealed`; `form` after the key went is learnt from the next list.

## Depends on
- `keys` (`prepare`, `sign`, `seal`), `sdk-core-wire` (the completion's `typ`, HPKE's info, `completionAad`, `paddedCompletion` and `completionLimits`, `payloads.completions`), `continuation-wire` (a delete's body), `passkeys` (the keys' list), `issuer`, `kernel` (the build context); the package's `record`.
