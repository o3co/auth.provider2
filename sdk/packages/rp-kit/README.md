# rp-kit

## Responsibilities
- The relying party's kit: the checks an RP (R16, R18) and an RS (R17) run on what the provider hands them, on the transparency log's contract (`transparency-wire`), which holds their inputs, their faults and what each depends on.

## Not here
- A token's standard verification (its issuer's JWKS, `iss`, `aud`, `exp`): the RP's OIDC library, before these checks.
- Fetching the status every τ_sdk, keeping each signer set's newest version, and closing the sessions of records the status later denies: the caller's loop around `checkReceipt` for now.
- The login screen's side: `login-screen`.
- The RP's DPoP keys, its own: one that refreshes makes a key for each session, each refresh family, as the provider binds a key to one family (Q27): a key given to a second family has that family's code exchange refused (`invalid_grant`), the code used up.
- A deployment at L0, whose receipts no log signs: R16 and R18 hold claim 3, which needs a signed receipt, so an RP there calls neither `checkReceipt` nor `checkCallback`, though its ID tokens still carry `esig` and `apr`.
- The receipt's `iss` (the log's name) against an expected one: `ReceiptCheck` names no expected log yet; the log's keys bind it for now.

## Offers
- `checkReceipt` (a `ReceiptCheck`): the token's receipt, or the first fault of `tokens.checks.receiptFaults` that holds. `notYetChecked` says to fetch the status again and take nothing until it covers the record.
- `checkCallback` (a `CallbackCheck`): `ok`, or the first fault of `tokens.checks.callbackFaults` that holds.

## Invariants
- It depends on the provider's protocol packages alone (the sdk's guard), and holds its own copy of the byte and JWS helpers the login screen holds: the sdk's packages depend on no other.
- A receipt is the log's, a bundle's of the check's frame, of the token's own digest (its header and claims, the receipt claim left out, as `tokens.digestInput` makes it) and of the flow expected, accepted no longer ago than `maxAge` and no later than now, σ aside each way (`tooOld`; `receipt`, read with the receipt itself, before its digest); a time given that is not a finite number fails it (`tooOld`). A token not of three parts has no receipt.
- A status is read before the record's place in it: JWS JSON General Serialization, each signature verified with its set's key of the protected header's kid and of the status's `typ`, each key counted once by its identity (whatever kids name it), at least the set's `required`; a set that is not the wire's `signerSet`, or of another purpose, verifies nothing.
- A status read, the record's shard is one the status names (its own member, never a name every object answers), the record at or below its watermark, and not among the not-accepted ids.
- A callback's proof is ES256 under the key its header carries, whose thumbprint is the ID token's `esig`; its record is the ID token's `apr`; its issuer, client, state and code's hash are the expected, as are the ID token's issuer and audience.
- A log or status key with no `alg` verifies by its curve (EC P-256, Ed25519): an RSA key, which fits two algorithms, verifies nothing. The log's and the status's keys are EC P-256 or Ed25519 for that reason, though the wire's `publicKey` takes RSA too.

## Depends on
- `transparency-wire` (the inputs, the schemas, the faults, `digestInput`, `ecThumbprintInput`).
