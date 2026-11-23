# front-core-wire

## Responsibilities
- Holds the contract of the wire from the Front to the Core: the frame's form, each operation the Core opens to the Front with its fields, the replies, the codes a rejection answers and the refusals' words. The Core holds this contract; the Front speaks it.

## Not here
- Encoding and decoding frames: `front-core-codec`, the one implementation both sides use.
- Reading what a field means (a JAR, an assertion, a DPoP proof): the Core's verifier of each.
- The connection, TLS and who may reach the Core: the http axis's adapters.

## Offers
- `version`, `headerLength`, `maxRequestBody` and `maxReplyBody`: the frame's version byte, its header's length, and its bodies' limits.
- `requests`: each operation by name, with its `code` and its `fields` in order (`FieldSpec`: name, type, least and greatest length, and an enum's count of values). A length of 0 is "not sent".
- `FieldType`: `bytes`, `utf8` (valid UTF-8 with no control character), `visible` (0x21 to 0x7e), `b64url`, `jws` (three base64url segments joined by two dots) and `enum` (one byte below its count).
- `grant` and `clientAssertionType`: the token request's enum values.
- `wireErrors`: the fixed code of each rejection; `outcomes` and `replies`: each reply's outcome and its fields; `refusals`: the OAuth errors a refusal names, its `error` the word's place plus one.

## Invariants
- A protocol (G33): types and frozen constants; no I/O, clock, randomness or state.
- Each operation has a code of its own, and each field a length range a u16 holds; every operation's fields at their greatest fit within `maxRequestBody`.
- A rejection's code is never 0, and carries no piece of the input.

## Depends on
- Nothing in the workspace.

## Vocabulary
- frame: one request or reply on the wire, header and body.
- operation: what the Core does for one kind of request the Front relays.
