# passkey-key-wire

## Responsibilities
- Holds a passkey's public key as the screen and the Core both read it: its JWK, its thumbprint's members alone, what its thumbprint (RFC 7638, RFC 8037) is the SHA-256 of, and the vectors both sides run, from one place.

## Not here
- Which algorithms a ceremony may offer (COSE's -7, -8, -257), and a thumbprint's value as a statement or a completion names it (`key_jkt`): `sdk-core-wire`.
- Reading a key from WebAuthn's COSE_Key or a SPKI, and hashing: `webauthn` and the screen's SDK.

## Offers
- `passkeyThumbprintInput` (a JWK): the JWK's required members in RFC 7638's order, with no space; none for a JWK that is not a passkey's (`PasskeyPublicJwk`).
- `test/keys.vectors.json`: each algorithm's key (COSE, SPKI, JWK, thumbprint input and thumbprint) and keys refused, which every reader runs.

## Invariants
- A protocol (G33): types, frozen constants, fixed schemas and the functions that build by them; no I/O, clock, randomness or state. It depends on no package of the workspace (G2, G6).
- A passkey's key is ES256 (P-256), EdDSA (Ed25519 alone) or RS256 (a modulus of 2048 to 4096 bits, exponent 65537). A JWK holds its thumbprint's members alone, each in its one unpadded base64url spelling: x and y 32 bytes, an odd modulus whose first byte is not 0 (refused, never cut). A P-256 point off its curve is refused by each side's crypto; an Ed25519 x is taken as its 32 bytes, one that is no point failing at its signature.
- A key travels as its COSE_Key bytes: CTAP2's canonical CBOR, a map of its key type's labels alone (1, 3, -1, -2, and -3 for EC2), in order, each once, of definite lengths, its integers shortest; the vectors hold each key's one COSE form.

## Depends on
- Nothing in the workspace; `zod` (a peer).

## Vocabulary
- thumbprint: the SHA-256 of a JWK's required members, base64url (RFC 7638). key type: EC (P-256), OKP (Ed25519) or RSA.
