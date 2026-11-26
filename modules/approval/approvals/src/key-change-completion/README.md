# key-change-completion

Internal module of `approvals`: a key change's completion, of the key a used possession names.

## Responsibilities
- Signs a used possession's key-change completion and seals it to its screen, once its change took, and keeps it with the purpose it was asked for.

## Not here
- Whether the change took, and placing it: the caller's (`passkey-management`). The flow: `completion` alone touches it.

## Offers
- `keyChangeCompletionsOver` → `completeKeyChange` (a used possession's hash, its path's purpose `first-key`, `passkey-add` or `sign-up`, what the change's record was given on the log): the `keyChange` completion of the key the possession names.
  - A sign-up's first keeps the possession's credential on its T (`signUp.credential`), unless the T kept another (`other`). Its possession's creation is the one its T's sign-up step answered, of basis `sign-up`, both records verified by this generation's ring (`creation` otherwise).
  - A possession of a sign-up's creation asked for another purpose is refused `creation`.
- `keyChangeCompletionOf` (the build context) → `completeKeyChange`; `keyChangeCompletionTakes`, which its package names among its own takes.

## Invariants
- A key change's completion is asked by its caller once its change took, which this module does not see. Its change is the key the possession's items name, never one the caller gives.
- One is made only for a used possession, up to its record's end (a minute past its expiry: a change placed late is completed then), that the Core's ring of this generation verifies, in a form `sdk-core-wire`'s `keyChange` takes (else `form`): signed by the ring, sealed to the possession's screen under `completionAad` of the purpose and the possession's hash, kept with the purpose's digest.
- Past the record's end none is made, after a change took too. One made in that minute keeps the possession's `exp`, its `iat` past it: its reader bounds the receipt's acceptance, not `exp`.
- Kept, it is given again alike for that purpose, with what the log gave as first asked; another purpose is `other`.

## Depends on
- `keys` (`prepare`, `sign`, `seal`), `sdk-core-wire` (the completion's `typ`, HPKE's info and `completionAad`, `payloads.completions.keyChange`), `issuer`, `kernel` (the build context); the package's `record`.
