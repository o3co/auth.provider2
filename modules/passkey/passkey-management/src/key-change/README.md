# key-change

Internal module of `passkey-management`: a first key's change, written as its kind's writer (KE-C01, C02, C04).

## Responsibilities
- Registers the key change's kind with its own record, and writes a first key's change: decided on its verified reservation, sent, taken in to its end, the subject's keys settled where it took.

## Not here
- The reservation, its verification and the checks a commit makes: `passkeys`' `registrations`. The order of the ops, the log and its judgments: `transparency`. The statements and the assertion it carries: the registration that asks.

## Offers
- `keyChangeKind`: `passkeys`' kind with the package's part's preimage record (`keyChangePart`, the contract's) after its own, not bundled, its resend that record's stage where it is a first key's change of that op, the record removed at the end.
- `keyChangesOver` (`registrations`' commit, `transparency`'s send, step, tend and `receiptOf`, `passkeys`' settle, the log's digest, a pause and the looks) → `change` and `receipts`, each of a `FirstKeyChange` (subject, reservation, verification, credential, public key, the creation and possession as signed, the new key's assertion).
- `change` → `took` with the log's receipts, `refused` with passkeys' word (`CommitRefusal`), or `ended`. `receipts`: a change placed already, its receipts as the log first answered them, its stage made again alike; none for one not placed, or placed with other content.

## Invariants
- The change is decided with its stage kept in the same write, so another replica resends it as sent; the stage's preimage is the creation, the possession and the assertion, in that order, and the first key's content; its receipt binds the possession's and the assertion's SHA-256 (base64url, over their text as sent), as `authority-rules`' envelope check digests them.
- A first key is approved by none and removes none. A first stage refused as `prevMismatch` closed the op with nothing on the flow: it is decided again, a few times at most. A flow open or not taken in is tended before it is decided again; a decision that moved or ran late is tried again.
- Whenever it takes an end in, its own step or a tend, that may be a key change's `took`, it settles the subject's keys, as passkeys asks of whoever takes one in; so too where its step goes past its stage's position, which another took in already.
- `took` is its own end alone, taken in as its owner; `ended` is any other end, its end taken in by another replica, or its stage on the flow already, which says nothing of whether the key is held: its caller reads the subject's keys. `refused` carries passkeys' words alone; any other refusal of the flow, no end within the looks, or a send refused, is unavailable: the reservation and its stage stay for another replica.

## Depends on
- `passkeys` (`registrations`, `settle`, the key change's kind), `transparency` (send, step, tend, `receiptOf`; the stage), `transparency-wire` (the preimage), `kernel`.
