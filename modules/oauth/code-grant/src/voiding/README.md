# voiding

Internal module of `code-grant`: voiding a code that came again, and retrying what failed.

## Responsibilities
- Lists a code void, marks it and revokes its token; on each host, every `sweep-interval`, settles again every code still listed.

## Not here
- Using a code up and deciding it came again (the grant). How a token is revoked (`tokens`).

## Offers
- `voiding` (the code store, the redemption records, the void list, tokens, log) → `settle` (one code's name) and `sweep` (one pass over the list).

## Invariants
- Trade-offs: whoever holds a leaked code can revoke the legitimate token while the code lives, as a reuse needs no key; a client that resends a redemption by itself fails it; a right redemption whose code ends while its token is made is refused, its token revoked.
- A code is listed first, whatever it holds, then marked void on its own record and its redemption record, which the redemption issuing it reads after issuing. A listed code's token is revoked, then it leaves the list.
- One whose token is not yet noted stays listed: the request issuing it reads the mark and voids again. One with no redemption record yet stays listed while its code is kept, as the redemption that used it up may still make one. One with neither record is logged and removed.
- A crash between a code's use-up and its redemption record keeps a reuse listed until the code ends; so does a code refused at the record's creation for its erased subject (`erased`), its entry staying until the code ends.
- A code that comes again after its own record ended is settled where its redemption record is there, which outlives it: its token is revoked from that record.
- A record gone is never written back; a mark rewrites what the record holds and keeps its end.
- Settling a code twice, on two hosts at once, does no harm.

## Depends on
- `kernel` (log, `Unavailable`), `tokens` (revoking by reference); the package's records and store interfaces.
