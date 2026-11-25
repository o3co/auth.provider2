# receipt-gate

Internal module of `transparency-wire`: the token receipt gate (A29, R16–R18, A38): the receipt a token carries, what a token's digest covers, `esig`'s input, the callback's proof, and the words and inputs of the receivers' checks.

## Responsibilities
- Holds the receipt the log signs for a record, and the claim a token carries it in, to its schema.
- Gives what a token's digest covers and an ID token's `esig` input, from texts read the one way (`text`).
- Holds the receivers' checks' frames, faults and inputs (R16–R18), and the callback's proof the login screen signs with E_sig.

## Not here
- What a token's digest covers: the package's invariant, on the root card, as the Core's writers digest tokens too.
- Running the checks, fetching the status every τ_sdk and keeping each signer set's newest version: the receivers' (the SDK's). Signing a receipt or a proof: each side's own.
- The status and the JWS a signer set signs it in: `judging`. The signer set and the public key: `signed-bodies`. The record, its digests and `recordRef`: `records`.

## Offers
- `tokens`: `claim` (`txr`), `frames`, `parse`, `digestInput` (header, claims) → the input or why not, `ecThumbprintInput` (a JWK) → the input or none, `checks` (`frames`, `receiptFaults`, `callbackFaults`).
- Schemas: `receipt`, `callbackHeader`, `callbackProof`, `idTokenEvidence`.
- Types: `Receipt`, `ReceiptFault`, `CallbackFault`, `ReceiptCheck` (R16, R17), `CallbackCheck` (R18).

## Invariants
- A callback's proof is ES256 under E_sig, its header carrying the key; its `code_hash` is the code's whole SHA-256 (not `c_hash`), its `iat` bearing no freshness. `esig`'s input is an on-curve P-256 key of exactly `crv`, `kty`, `x`, `y`, canonically encoded.
- A receipt names a token (its frame and digest) where it is a bundle's alone; approval digests go with an approval's, key change digests with a key change's.
- A check names the first of its faults that holds, in the order listed, but for `status`: a status it cannot read is named before the position and the deny list are read (`notYetChecked`, `denied`), which need it.

## Depends on
- `records` (the field forms, the writer, the digests, `recordRef`, the P-256 key), `signed-bodies` (`SignerSet`, `ReceiverKey`: types alone), `text` (the one reading, `canonical`, the P-256 point), `words` (`frames`, `logTyps`, `recordKinds`); `zod`.
