# signed-bodies

Internal module of `transparency-wire`: the signed bodies of the records no Core writer writes (the monitor's, the publisher's and the generation flow's), the signer sets, and such a record read with its verified body.

## Responsibilities
- Holds each body a monitor, a publisher or people's keys sign to its kind's schema, and a signer set to its purpose and count.
- Holds a record no Core writer writes to the body its signature verified, so the envelope and the body name the same flow, op and position.

## Not here
- The record's envelope, its writer role and kinds, and the op ids: `records`. Verifying the signature: each side's own.
- A registry version's and a config version's body: not this wire's.

## Offers
- `signers`: the counted purposes (`stopInstruction`, `restartApproval`, `resetInstruction`), each `required` of at least `least` keys.
- `bodies`: `keySet`, `confirmation`, `denial`, `erasureBoundary`, `resetBoundary`, `tombstone`, `coreRingKey`, `signerSet`, `stopInstruction`, `restartApproval`. `signerSet`; `signedRecord` (`record`, `body`).
- `publicKey` (an EC, OKP or RSA public key). Types: `SignerSet`, `ReceiverKey`.

## Invariants
- A signed body must match its record's envelope (`signedRecord`): an erasure boundary's, a reset boundary's (a subject's, one last stage) and a tombstone's name their flow, op and previous position, a reset's op is derived from its instruction's id and a stop's from its generation, a restart names its previous position.
- A signer set's version only grows per purpose; a reader takes none older. A stop instruction is signed by one key, a restart approval by two of three or more. The install approval names no previous position, generation nor evidence.

## Depends on
- `records` (the field forms, the written record, the key set, `opIds`, `coreKinds`), `words` (`logTyps`), `text` (the payload's reading); `zod`.

## Vocabulary
- generation (Core の世代), stop instruction (停止の指示), restart approval (再起動の承認), install approval (導入の承認), Core ring key record (Core の ring の鍵の記録), signer set (署名の組), reset instruction (reset の指示), reset boundary (reset の境界).
