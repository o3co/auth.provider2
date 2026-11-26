# key-change

Internal module of `passkey-management`: a key change written as its kind's writer (KE-C01, C02, C04): a key added, a first key or one a passkey-add approved, and a key a passkey-manage deleted.

## Responsibilities
- Registers the key change's kind with its own record, and writes a key added's change, decided on its verified reservation, or a key deleted's, decided on its removal: sent, taken in to its end, the subject's keys settled where it took.

## Not here
- The reservation, its verification and the checks a commit makes: `passkeys`' `registrations`. The order of the ops, the log and its judgments: `transparency`. The statements and the assertion it carries: the registration that asks.

## Offers
- `keyChangeKind`: `passkeys`' kind with the package's preimage record (`keyChangePart`) after its own, not bundled, resending that record's stage for its op, removed at its end.
- `keyChangesOver` (`registrations`, `transparency`, `passkeys`' settle, the log's digest, a pause, the looks, the clock) → `change` and `receipts`, each of an `AddedKey` (subject, reservation, verification, credential, public key, creation and possession as signed, the new key's assertion, the register continuation behind the possession; `approved`; `signUp`, a sign-up's T).
- `Approved`, where a passkey-add approved the key: the passkey-add and its assertion, the approving key's credential and registration, the statement's use-once mark, the creation's key generation.
- `change` → `took` with the log's receipts, `refused` with passkeys' word or its decision's own (`CommitRefusal`), or `ended`. `receipts`: a change placed already, its receipts as the log first answered them, its stage made again alike; none for one not placed, or placed with other content.
- `remove` and `removed`, each of a `DeletedKey` (subject, credential, op, one per continuation; `approval`: the passkey-manage, its assertion, the approving key's credential and registration, the mark; the continuation: number, body, signature; `until`, its expiry; `heldUntil`, its call's hold's end).
- `remove` → as `change`, `refused` in `RemoveRefusal`'s words (passkeys' `unknown`, `last`, `op`; its own `approver`, `used`, `expired`); `removed`: a deletion placed, as `transparency`'s `applied` answers it, taken in through its position (`Removed`: `none`, `took` with receipts, settled; `didNotTake`); asked again within the looks while unjudged or a live owner elsewhere holds its end, then thrown: each look one `applied`, up to 18 a recovery and 36 a managing step.

## Invariants
- The change is decided with its stage kept in the same write, so another replica resends it as sent; the stage's preimage is the creation, the continuation (canonical JSON of its body, sequence number and signature), the possession and the assertion, in that order, and the first key's content; its receipt binds the possession's and the assertion's SHA-256 (base64url, of their text as sent), as `authority-rules`' envelope check does.
- A passkey-add's preimage names the approving key's registration as parent, its evidence the passkey-add, its assertion, the creation, the continuation, the possession and the new key's assertion, in that order, and the added key's content. Its changes are the key by that parent and the statement's mark consumed, as `authority-rules`' fold reads the record.
- Its decision, on the applied state, refuses where the approving key is not live under that registration with that credential (`approver`), the mark is consumed (`used`: one key from one passkey-add), or the creation's key generation is not the flow's (`fenced`). A reservation refused so stays verified until it lapses, holding the subject's other registrations; only the screen signing its continuations causes it.
- A sign-up's (F1) preimage is a first key's, its T as signed before the creation; approved by none. Its change is its flow's first record: a second, under another op, the rules refuse. The T's `signUp.credential` is `approvals`' to write, as it completes the change; this writer writes none.
- A sign-up's record placed that does not take (held, abandoned) leaves its subject, made with no identifier, a flow no first key takes: that subject and its T are dropped, the person starting again from the authorization.
- A first key is approved by none; neither removes any. A first stage refused `prevMismatch` closed the op with nothing on the flow: decided again, a few times. A flow open or not taken in is tended before it is decided again; a decision that moved or ran late is tried again.
- Whenever it takes an end in (its own step or a tend) that may be a key change's `took`, it settles the subject's keys, as passkeys asks; so too where its step goes past its stage, another having taken it in.
- `took` is its own end alone, taken in as its owner; `ended` is any other end, its end taken in by another replica, or its stage on the flow already, saying nothing of whether the key is held. `refused` carries passkeys' words and its decision's own alone; any other refusal of the flow, no end within the looks, or a send refused, is unavailable: the reservation and its stage stay for another replica.
- A deletion's preimage names the approving key's registration as parent, its evidence the passkey-manage, the approving key's assertion and the continuation (as a first key's), in that order, its content the key named; its receipt binds the passkey-manage's and the body's SHA-256. Its changes are that key removed (DelDrop: the keys it approved stay) and the statement's mark consumed, as `authority-rules`' deletion and fold read the record.
- Its decision, on the applied state, refuses where the approving key is not live under that registration with that credential (`approver`: a key deleting itself is decided before going), the mark is consumed (`used`: one key a passkey-manage), the passkey-manage expired (`expired`), the call's hold ended (thrown: its number may be another's), or the key named is none of the subject's (`unknown`); passkeys refuses the last (`last`).

- `expired` is read on the clock, not as a write's deadline.

## Depends on
- `passkeys` (`registrations`, `settle`, the kind), `transparency` (send, step, tend, `receiptOf`, `applied`; the stage), `transparency-wire` (the preimage), `kernel`.
