# statement

Internal module of `approvals`: issuing statements and using each once.

## Responsibilities
- Signs a statement of one purpose over its items, under the common fields (the wire version it writes, the latest `sdk-core-wire` speaks; issuer, id, times, the screen's keys, a nonce but for T), and records it by its hash.
- Uses a statement once, and answers the approval from its record.

## Not here
- Continuations (`continuation`). The completion and the flow (`completion`).

## Offers
- `statementsOver` (`StatementParts`) → `issue`, `use`, `usedOf`. `declaredOf` (the declarations, a refusal) → each purpose's declared names. `itemNames`, `itemsIn`, `challengeOf`, `sha256`; the record's shape (`recordOf`, `stored`).

## Invariants
- `issue` checks the items against the declared names and the purpose's schema, and the screen's `eEnc` as a P-256 point, before anything is counted or signed; counts all statements and the caller's key in `issue-window`; refuses past `max-concurrent` signings in this process.
- A creation's challenge is for `create()`, any other's for `get()`.
- The record is kept a minute past the statement's expiry, so a late use reads as expired.
- A use writes once, from issued to used, holding what used it and when: an assertion's subject, credential and JSON text as sent, or a verification. Its answer is the approval only where the record holds that same evidence; any other is `used`.
- A record of another shape is read as a store that cannot tell: unavailable.
- A use reads the record by the hash of the bytes presented, and takes them only where they are the bytes recorded and the Core's ring of this generation verifies them.

## Depends on
- `keys` (`prepare`, `sign`), `passkeys` (`assert`), `rate-limit` (`hit`), `sdk-core-wire` (schemas, canonical text, the challenge's input).
