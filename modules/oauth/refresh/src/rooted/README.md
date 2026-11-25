# rooted

Internal module of `refresh`: a subject's families by their root key, ended when that key goes (Q46).

## Responsibilities
- Lists each family founded under its subject and its root key's credential (its approval's passkey), and ends a subject's families rooted in a credential removed, or all of a subject's when it is left with no key.

## Not here
- Which families the log drops for a key's deletion or a reset (DelDrop, NextGen): `authority-rules`' fold. Telling a removal: `passkeys`' settle. Founding a family, revoking one, and the DPoP key's claim (Q27): the package's `family` and records.

## Offers
- `rootedOver` (the records, the delegation's length L, the clock) → `list` (a family founded: its subject, id and credential) and `rooted` (`RootedFamilies`: `end` by subject and credential, `endAll` by subject).
- `removalOver` (`RootedFamilies`) → `passkeys`' `PasskeyRemoval`: `removed(subject, credential, emptied)` read here alone, `emptied` ending all of the subject's families, else those rooted in the credential.

## Invariants
- A family is listed in its founding's bucket of L, `s.<bucket>.<subject>`, created for its subject with a life of 2L and a margin. A family live now ends within L of its founding: `end` and `endAll` read this bucket, the one before, and the one after for hosts' clocks drifting apart.
- A bucket lists `listedPerBucket` (64) families, a bound on one record's size; one past them is not listed. A family not listed, and a removal not told, are held by the log's rules (DelDrop, NextGen, J7) and the family's end.
  - L changed (`refresh.lifetime`) moves the buckets: lists made before it go unread until their families end, held so too.
- Ending is a revocation (`revokeFamily`): the DPoP key the family is bound to stays claimed to its end (Q27).
- The root key is the family's recorded credential, its approval's passkey: the families `end` takes are those DelDrop drops.
- A failure is thrown: listing, at founding, ends the family it would have held; a removal's, so the next settle tells it again.

## Depends on
- `passkeys` (`PasskeyRemoval`, at its boundary), `kernel`; the package's records and store.
