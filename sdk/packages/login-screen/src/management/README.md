# management

Internal module of `login-screen`: the keys' management (V22: `passkey-add`, `passkey-manage`).

## Responsibilities
- Reads a management statement, takes its approval's completion (passkey-manage's keys' list, or passkey-add's creation), and sends and reads a delete's or rename's sealed continuation.

## Offers
- `management`:
  - `read` (the statement, the purpose asked for, the ring, the screen keys, the issuer) → a `ReadManage`, or a statement's refusal (another purpose's is `payload`).
  - `finish` (a `ReadManage`, sealed, the ring, the screen keys, the issuer, the assertion's bytes): the approval's completion under `completionAad` of its purpose, read only padded to one of sdk-core-wire's buckets (`unpaddedCompletion`; else `open`): passkey-manage's keys' list (a rename's `continued` refused), or passkey-add's creation as a `ReadCreation` (its `basis` passkey-add, its evidence the statement's hash) that `firstKey`'s next steps take; or why not (`ManagementFinishError`).
  - A passkey-add's creation goes on only where it names its approving key (V30) and the screen's own assertion verifies under it (internal module `assertion`), before any `create()`: another key is `approver` (one naming none does not read, `creation`); a key this browser cannot verify is `unsupported`.
  - An RS256 key approves no passkey-add in 0.1.0: the Core refuses one with its generic refusal, after the person's tap, so an add refused by the Core may be that; the screen never sees an RSA key or the reason.
  - `continuation` (a passkey-manage `ReadManage`, `delete` or `rename`, the sequence 1 to 16, the body, the screen keys and the Core's sealing key) → the sealed value (V24): the body and its E_sig signature over the plaintext body's hash, padded to one length and bound to stage, statement and sequence, and what was sent (`Continued`); or why not. A resend sends the same sealed value, kept by the caller.
  - `renamed` (a rename's `Continued`, the sealed answer, as `finish` takes and reads, padded): the new keys' list, its `continued` naming exactly the rename sent (sequence, body's hash), and `applied`, whether the key the rename named holds, in that list, the label sent (the Core keeps a label as sent): a rename that did not take (another's key, or a later rename taken first) is answered with the list too, and is false; or why not (a `Continued` that is no rename's among them).
    - A list's `created_at` is in seconds; 0 where the Core cannot tell, its label then `Passkey`, no date to show.

## Depends on
- `sdk-core-wire`, `continuation-wire`.
- The package's `statement`, `completion`, `hpke`, `jws`, `keys`, `challenge` and `bytes`; the package's `first-key` (`ReadCreation`, the creation's next steps) and `assertion` (`verifiedUnder`).
