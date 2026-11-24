# front-core-wire

## Responsibilities
- Holds the contract of the wire from the Front to the Core: the frame's form, each operation the Core opens to the Front with its fields, the replies, the codes a rejection answers and the refusals' words, and how each operation and refusal is carried over HTTP. The Core holds this contract; the Front speaks it.

## Not here
- Encoding and decoding frames: `front-core-codec`, the one implementation both sides use.
- Reading what a field means (a JAR, an assertion, a DPoP proof): the Core's verifier of each.
- The connection, TLS and who may reach the Core, and reading or writing HTTP: the http axis's adapters.

## Offers
- `version`, `headerLength`, `maxRequestBody` and `maxReplyBody`: the frame's version byte, its header's length, and its bodies' limits.
- `requests`: each operation by name, with its `code` and its `fields` in order (`FieldSpec`: name, type, least and greatest length, and an enum's count of values). A length of 0 is "not sent".
- `FieldType`: `bytes`, `utf8` (valid UTF-8 with no control character), `visible` (0x21 to 0x7e), `b64url`, `jws` (three base64url segments joined by two dots) and `enum` (one byte below its count).
- `grant` and `clientAssertionType`: the token request's enum values.
- `wireErrors`: the fixed code of each rejection; `outcomes` and `replies`: each reply's outcome and its fields (a refusal's `retryAfter` among them); `refusals`: the OAuth errors and the limits' words (`rate_limited`, `too_many_attempts`) a refusal names, its `error` the word's place plus one (a word added goes last).
- `overHttp`: each operation as HTTP (`OverHttp`: a POST's path, a form or JSON body, `bodyNames` and `headerNames`, `enumTexts` (`EnumTexts`), the `discriminator` telling apart operations sharing a path, the `successStatus` (200 unless said), whether a page of another origin calls it, and its `answer`'s form), the status of each refusal (every other `400`), and `declaredSource`; the rules of the text (base64url bytes, decimal or `other` enums, an empty text not sent) are in its doc comment.

## Invariants
- A protocol (G33): types and frozen constants; no I/O, clock, randomness or state.
- Each operation has a code of its own, and each field a length range a u16 holds; every operation's fields at their greatest fit within `maxRequestBody`.
- A rejection's code is never 0, and carries no piece of the input.
- Every operation is carried over HTTP, each field once; operations sharing a path differ by one body value, all but one.
- Every operation is a POST: one that would need another method is not opened to the Front.
- Every operation the screen calls names its answer's form, one per value where an enum field decides it (`continue`: `register` a statement, `delete` and `rename` sealed). The names are sdk-core-wire's, which this wire does not depend on: a package reading both checks them.
- The screen's key operations (§C): `firstKeyRecover` (a lost creation asked again), `approvalStart` and `approvalFinish` (`passkey-add`, `passkey-manage`), `continue` (`register`, `delete`, `rename`) and `keyFinish` (a key change's possession and the new key's assertion, on any path). `firstKeyContinue` and `firstKeyFinish` stay until their callers move.
- `continue` carries a sequence of 0 to 16 (0 the Core's to refuse), a statement up to 8192 (a creation's excluded credentials among it), and per stage: `register` a body (the registration's response as sent) and `sig`, no `enc` nor `ct`; `delete` and `rename` `enc` (65) and `ct` (2064) alone, the body and its `sig` sealed inside (V24), `body` and `sig` empty. Any other mix, or an empty field a stage needs, is the Core's to refuse.
- A field that is "one of" another (the login's start's `request` and `requestUri`) is of length 0 alone on the wire, which reads lengths only: the Core refuses both or neither.
- Every operation's first field, `source`, is the source the Front determined (its address, as its trusted proxies tell it), empty where it could not: the Front's declaration, which the Core counts by only while the Front is honest.

## Depends on
- Nothing in the workspace.

## Vocabulary
- frame: one request or reply on the wire, header and body.
- operation: what the Core does for one kind of request the Front relays.
