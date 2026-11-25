# sealed

Internal module of `passkey-management`: a first key's sealed requests opened.

## Responsibilities
- Opens a stage's sealed request under the Core's sealing key, and reads its plain text by the stage's shape.

## Not here
- The sealing and its key: `keys`. The additional data's form, the stages' shapes and HPKE's info: `sdk-core-wire`. The nonce's use: internal module `nonces`.

## Offers
- `openSealed` (the keys' opening, stage, `SealedRequest` as `front-core-wire` carries it, the stage's shape) → `opened` (its plain text, its digest, the screen's keys), `unopened` or `withdrawn`. `digestOf`, `screenOf`.

## Invariants
- The additional data is `sdk-core-wire`'s `firstKey.aad` of the stage, the nonce and the screen's keys the request names, so a request whose keys were swapped does not open; its info is `hpke.info.firstKeyRequest`.
- Screen keys of no P-256 point are `unopened`, the holder never asked. Text not UTF-8 JSON, or of no shape the stage takes, is `unopened`, as a sealing that does not open is.
- The digest is the SHA-256 of the sealing's `enc` then `ct`: the request's name to its nonce and its answer, and a creation's `ct_hash`.
