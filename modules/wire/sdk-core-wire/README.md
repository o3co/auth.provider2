# sdk-core-wire

## Responsibilities
- Holds the contract between the login screen and the Core, which the Core holds and the screen follows; the Front relays it unread. Its words, the payloads' schemas, the rule that makes T's items from a JAR, and the inputs each hash and signature covers are written here once, so both sides build the same bytes.

## Not here
- Hashing, signing, sealing and verifying: the screen's SDK and the Core, each its own.
- How a request crosses the Front: `front-core-wire`.

## Offers
- `typs`: the `typ` of a JAR, the statement T (`approval+jwt`), the completion's answer (`completion+jwt`, apart from T), a client assertion and a DPoP proof. `purposes`: `authorization`, `creation` and `possession`.
- `hpke`: the suite (`DHKEM(P-256, HKDF-SHA256)`, `HKDF-SHA256`, `AES-128-GCM`) and the info of each sealing: the completion, the first key's request and its code.
- `jarClaims`: an authorization's closed set of `items`, those a JAR must carry (`required`), and its `envelope`, the claims that are no item.
- `itemsFromJar` (payload, the JAR's hash): T's items, or an error naming the claim unknown or missing, or the value not allowed.
- `payloads`: the schemas of T, the completion's answer, the `creation` and `possession` statements, and what the Core opens of the first key's start and mail's side and the screen of the start's answer. Their types: `StatementPayload`, `CompletionPayload`, `CreationPayload`, `PossessionPayload`, `AuthorizationItems`, `SigningKey`.
- `canonicalJson`, `challengeInput`, `evidenceInput`, `firstKeyAad` and `continuationInput`: what a challenge, the evidence's value, a sealed request's additional data and a continuation's signature cover. `firstKeyStages`: `start` and `mail`.

## Invariants
- A protocol (G33): types, frozen constants, fixed schemas and the functions that build by them; no I/O, clock, randomness or state.
- Every payload refuses a field it does not know; T's items are a closed set, and a JAR with any other claim beside its envelope yields no items.
- The identifier never goes into a statement but masked, for display alone.
- A challenge's input names its use, and the evidence's its purpose, each apart from the value by a NUL.

## Depends on
- Nothing in the workspace; `zod` (a peer).

## Vocabulary
- statement: what a person approves with a passkey, signed by the Core's ring; T is an authorization's.
