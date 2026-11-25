# reading

Internal module of `webauthn`: what the ceremonies and the evidence checks read of a response alike.

## Responsibilities
- Reads a response's client data, judges its frame against the pages that may frame a ceremony, tells a challenge's one spelling, and reads a new key whole from its authenticator data.

## Not here
- What a response proves (`ceremony`, `evidence`).

## Offers
- `RelyingParty`; `clientDataOf`, `isChallenge`, `frameRefusal`, `keyReadWhole` (a new key in its one COSE_Key form, the very bytes after the credential id, then nothing or one map of extensions where flagged).

## Invariants
- Client data that is not a JSON object reads as none. A challenge is 32 bytes in their one unpadded base64url spelling.
- A reported top origin not listed, or not in a frame, is `top-origin`, and so is any frame when none is listed.

## Depends on
- `@simplewebauthn/server` (its decoders alone); the package's contract and key reading.
