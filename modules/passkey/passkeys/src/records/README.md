# records

Internal module of `passkeys`: its records in its part of a subject's flow, the owner of the keys in the flow's state, the key change's kind, and the pure rules of a key change.

## Responsibilities
- Holds the shapes of passkeys' records and reads each: the keys and the key generation, the reservation, a credential's record, the notices of keys gone, and what the last settle told of.
- Owns the keys and the key generation in the flow's state (`keysOwner`): its write notes each credential a Step takes off.
- Owns the key change's kind but its writer's parts (`keyChanges`): its part, its records and its end.
- Decides a registration's and a removal's key change (KE-C01) on the reservation and the flow's state, with the time, the most keys and the writer's own deciding.

## Not here
- Writing the reservation, the credential records and the bindings, and running a key change's decision on the frame (`transparency`'s `decide`): `registering`. Reading the keys for an assertion, and the settle: `kept`.
- The fold and the state's schema: `authority-rules`. The frame, its owners and the kinds' registry: `transparency`.

## Offers
- `part`, `flowOf`, `unitOf`; `keysOf`, `activeKey`, `credentialsOf`; `reservationOf`, `pendingAt`, `asJson`; `credentialRecordOf`; `noticesOf`, `noticesKept`; `settledOf`, `settledRecords`; their types.
- `keysOwner`, `keysRecords`; `keyChanges`, `reservationRecords`.
- `committing` (the reservation and its verification, the time and the most keys, the writer's deciding) and `removing` (the credential and the op, the writer's deciding) → a `Deciding` for `transparency`'s `decide`.

## Invariants
- A keys record, notices or a credential's record of another shape throws, refused by its schema (zod's error); a reservation or a settled record of another shape reads as none, deciding nothing.
- The keys owner writes the keys only where they changed, and the notices only where a Step took a credential off: each gone numbered on from the last, the latest 64 kept.
- The kind's end confirms a verified reservation whose op it is where its key took (`active`), and ends it on `held` or `abandoned`; any other end leaves it verified.
- `committing` refuses, before asking the writer: an unknown or replaced reservation, one not verified, another verification, one lapsed, one under another key generation (a reset since), a first one where a key is held, a credential already active, and the most keys held.
- `removing` refuses the reservation's op, then the writer's own refusals on the same state, then a credential not active and the last key (DelDrop: the key alone goes, the keys it approved stay).
- A `TypeError`: on a registration, the writer's changes carrying no key or another, approving a first key or approving by none one not first, or removing one; on a removal, removing another key than the one named, or none, or adding one; a writer giving another count of records than were read.
- The writer's own records of the kind are kept as it wrote them; passkeys' reservation, first, is left.

## Depends on
- `authority-rules` (the state's schema), `transparency` (the frame's types, owners and kinds), `transparency-wire` (`Flow`), `zod`.
