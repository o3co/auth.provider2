# claims-selection

## Responsibilities
- Decides which claim names a `claims` request parameter may release (OpenID Connect Core §5.5), by the client's allowance and what the person agreed to in the approval the request rests on (O19), and keeps that selection and its value constraints for the code and each access token it gives.

## Not here
- Reading the `claims` parameter, which claims a name stands for, and the approval's items (`authorize`, `oidc`, `approvals`): the caller hands what was agreed. Releasing claims and checking values against constraints (`oidc`).
- A refresh family's selection: none is kept for a family; `refresh` and the family's target come with it.

## Offers
- Contract `claimsSelections`:
  - `scopeOf`: a claim's scope, as the contributed table of claim scopes tells it; none without one.
  - `select` (client, subject, asked, agreed: the approval's scopes and claim names): the names whose scope the client is allowed (`client-allowance`) and which the approval agreed to by scope or by name; every constraint kept, since constraints only hold back.
  - `keepForCode`, by the redemption's name, for the code's subject, for the code's lifetime and a minute more.
  - `forCode`: the selection pinned to a redemption; none for a code without one.
  - `forToken`: the userinfo target kept for an access token; none for a token without one.
- `selectionLimits`, `withinLimits` (whether a selection keeps within them) and the types `Agreed`, `Selection`, `Target`, `Named`, `Constraint` and `Scalar`.
- Extension point `claimScopes` (at most one, from the module releasing claims): `scopeOf(claim)`.
- Contribution to `code-grant`'s redemption hooks: the pin, for the code's subject, and a redeemed code's token kept the pinned userinfo target, for the pin's subject: a redemption told another subject or none is unavailable.
- Contribution to `erasure-extensions`' erasers: `claims-selection` (internal module `erasure`), its migration reading each record's own subject.
- Store interface `selectionRecords`, wired by the assembly: records by name, each created once for its lifetime and its subject (`create`, `erased` past the subject's erasure); `erase` and `migrate` together or neither, a part refusing the boot. Its needs (`selectionRecordsNeeds`): never evicted, survives a crash and a failover, confirmed reads, written by the provider alone.
- `./testing`: its contract test for every implementation (`selectionRecordsContract`, through faults), and claims-selection composed over records in memory (`claimsSelectionInMemory`), which a test may wrap.

## Invariants
- A name is released only where the approval agreed to it: no record of consent, standing from an earlier login, is read.
- A selection holds only scalar values: strings up to 256 characters, booleans and finite numbers; exactly one of `value` and a non-empty `values` of up to 16; 4 KiB whole. These are fixed, as a selection is stored and read back under the same bounds. Another is a `TypeError`.
- An empty pin means the code had no selection kept, never that claims requests are not taken; every redemption is pinned, once: a pin there already is unavailable.
- A pin copies the code's selection, or marks it none, and holds it five minutes; the redemption's other reads use only the pin. A pin gone fails the read, never answering none.
- A code still alive at its pin finds its selection, which outlives the code by a minute; a code past its life is refused by `code-grant` before anything reads its pin.
- Every record is written with its subject (format 2). One of another format or shape fails the read as unavailable, as a read the place cannot answer does; never answered as none.
- Writes and reads that fail throw to the caller. A write past its subject's erasure fails as unavailable; a record's own subject wins, and a caller's that differs fails as unavailable. A write a caller past the types gives no subject (`keepForCode`, the pin) is its bug, a `TypeError`, writing nothing.

## Data
- Records: a code's selection for the code's lifetime and a minute, so a code still alive finds it; a pin for five minutes, a fixed margin over the one exchange it covers; a token's target until the token's end and two minutes, for clock drift between hosts.

## Depends on
- `kernel`, `clients`, `client-allowance`, `code-grant`, `erasure-extensions`

## Vocabulary
- Selection: what a request releases beyond its scope (names) and what it holds back (constraints), by target.
- Target: the ID token or userinfo.
- Pin: a redemption's copy of its code's selection, read through that one exchange.
- Agreed: the scopes and claim names of the approval a request rests on.
